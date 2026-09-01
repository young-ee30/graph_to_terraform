#!/usr/bin/env python3
"""Core engine for OpenGraph to Terraform conversion and optional read-only AWS context collection.

This module never invokes Terraform, deploys resources, executes attacks, or mutates AWS.
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

VERSION = "1.1.0"

class PipelineError(RuntimeError):
    """Raised for invalid input, unsafe execution, or unsupported paths."""

@dataclass(frozen=True)
class Node:
    id: str
    kinds: tuple[str, ...]
    properties: dict[str, Any]

    @property
    def primary_kind(self) -> str:
        # OpenGraph nodes may carry generic kinds before an extension kind.
        # Prefer AWS/RNR semantic kinds so classification does not depend on list order.
        return next(
            (
                kind
                for kind in self.kinds
                if kind.startswith("AWS_") or kind.startswith("RNR_")
            ),
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
    hints: dict[str, Any] = field(default_factory=dict)

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
    # RNR integrated graph extension. These are evidence/model nodes produced
    # by the application and network collectors, not native AWSHound kinds.
    "RNR_Environment": "CONTEXT_REQUIRED",
    "RNR_ExternalSource": "L4_NETWORK",
    "RNR_LoadBalancer": "L4_NETWORK",
    "RNR_WAFWebACL": "L4_NETWORK",
    "RNR_SecurityGroup": "L4_NETWORK",
    "RNR_Subnet": "L4_NETWORK",
    "RNR_NetworkAcl": "L4_NETWORK",
    "RNR_NetworkFinding": "L4_NETWORK",
    "RNR_AppEndpoint": "L3_APPLICATION_DATA",
    "RNR_CodeFinding": "L3_APPLICATION_DATA",
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
    "RNR_HasFinding": "L3_APPLICATION_DATA",
    "RNR_CanCompromiseWorkloadRole": "L3_APPLICATION_DATA",
    "RNR_SafeSimulationReachesRoleMetadata": "L3_APPLICATION_DATA",
    "RNR_CanReach": "L4_NETWORK",
    "RNR_ForwardsTo": "L4_NETWORK",
    "RNR_ProtectedBy": "L4_NETWORK",
    "RNR_AttachedSecurityGroup": "L4_NETWORK",
    "RNR_ProtectedByNetworkAcl": "L4_NETWORK",
    "RNR_LocatedIn": "L4_NETWORK",
    "RNR_Contains": "CONTEXT_REQUIRED",
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
    "RNR_Contains",
    "RNR_ProtectedBy",
    "RNR_AttachedSecurityGroup",
    "RNR_ProtectedByNetworkAcl",
    "RNR_LocatedIn",
}

PATH_CONNECTOR_EDGE_KINDS = {
    "AWS_RunsAs",
    "AWS_ClusterHasNodeGroup",
    "AWS_NodeGroupHasRole",
    "RNR_CanReach",
    "RNR_ForwardsTo",
    "RNR_HasFinding",
    "RNR_CanCompromiseWorkloadRole",
    "RNR_SafeSimulationReachesRoleMetadata",
}

RNR_PATH_EDGE_KINDS = {
    "RNR_CanReach",
    "RNR_ForwardsTo",
    "RNR_HasFinding",
    "RNR_CanCompromiseWorkloadRole",
    "RNR_SafeSimulationReachesRoleMetadata",
}

RNR_SUPPORT_EDGE_KINDS = {
    "RNR_ProtectedBy",
    "RNR_AttachedSecurityGroup",
    "RNR_ProtectedByNetworkAcl",
    "RNR_LocatedIn",
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
        *RNR_SUPPORT_EDGE_KINDS,
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

    # A BloodHound query may export only one integrated RNR path.  RNR path
    # relationships deliberately remain non-traversable until runtime proof,
    # so their is_traversable flag must not be used as a discovery filter here.
    # Connected path edges are treated as one hypothesis and nearby network
    # control nodes are pulled in as supporting mirror context.
    rnr_path_edges = [
        edge
        for edge in edges
        if edge.kind in RNR_PATH_EDGE_KINDS
        and (
            edge.kind != "RNR_HasFinding"
            or nodes[edge.end].primary_kind == "RNR_CodeFinding"
        )
    ]
    rnr_unseen = {edge_identifier(edge): edge for edge in rnr_path_edges}
    while rnr_unseen:
        _, first = rnr_unseen.popitem()
        component = [first]
        component_nodes = {first.start, first.end}
        changed = True
        while changed:
            changed = False
            for key, edge in list(rnr_unseen.items()):
                if edge.start in component_nodes or edge.end in component_nodes:
                    component.append(edge)
                    component_nodes.update((edge.start, edge.end))
                    del rnr_unseen[key]
                    changed = True

        support = [
            edge
            for edge in edges
            if edge.kind in RNR_SUPPORT_EDGE_KINDS
            and edge.start in component_nodes
        ]
        support_nodes = set(component_nodes)
        for edge in support:
            support_nodes.add(edge.end)
        # A selected subnet may point to its NACL in a second support hop.
        second_hop = [
            edge
            for edge in edges
            if edge.kind in RNR_SUPPORT_EDGE_KINDS
            and edge.start in support_nodes
            and edge.end not in support_nodes
        ]
        support.extend(second_hop)
        for edge in second_hop:
            support_nodes.add(edge.end)

        indegree = {node_id: 0 for node_id in component_nodes}
        outdegree = {node_id: 0 for node_id in component_nodes}
        for edge in component:
            indegree[edge.end] = indegree.get(edge.end, 0) + 1
            outdegree[edge.start] = outdegree.get(edge.start, 0) + 1
        starts = [node_id for node_id in component_nodes if indegree.get(node_id, 0) == 0]
        targets = [node_id for node_id in component_nodes if outdegree.get(node_id, 0) == 0]
        start = next(
            (
                node_id
                for node_id in starts
                if nodes[node_id].primary_kind == "RNR_ExternalSource"
            ),
            starts[0] if starts else first.start,
        )
        target = next(
            (
                node_id
                for node_id in targets
                if nodes[node_id].primary_kind
                in {"AWS_S3Bucket", "AWS_S3Object", "AWS_SSMParameter", "AWS_Secret"}
            ),
            targets[0] if targets else component[-1].end,
        )
        digest = hashlib.sha1(
            "\n".join(sorted(edge_identifier(edge) for edge in component)).encode("utf-8")
        ).hexdigest()[:10]
        runtime_proven = all(
            edge.properties.get("runtime_exploit_proven") is True
            for edge in component
            if edge.kind == "RNR_CanCompromiseWorkloadRole"
        )
        scenarios.append(
            make_scenario(
                scenario_id=f"integrated-{digest}",
                scenario_type="integrated_rnr_path",
                start=start,
                target=target,
                seed_nodes=support_nodes,
                path_edges=component + support,
                nodes=nodes,
                all_edges=edges,
                mirror_mode="INTEGRATED_MINIMAL_MIRROR",
                reasons=[
                    "The input contains an RNR application/network path hypothesis.",
                    (
                        "Runtime compromise evidence is present."
                        if runtime_proven
                        else "Runtime compromise is not yet proven and must be validated in the mirror."
                    ),
                ],
            )
        )

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
        if all(
            edge.kind in STRUCTURAL_EDGE_KINDS
            or edge.kind in PATH_CONNECTOR_EDGE_KINDS
            for edge in component
        ):
            # A RunsAs/containment connector without a permission edge is
            # context, not an independently executable attack path.
            continue
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

def add_context_request(
    requests: list[ContextRequest],
    *,
    service: str,
    operation: str,
    arguments: list[str],
    reason: str,
    required: bool = True,
    region: str | None = None,
    hints: dict[str, Any] | None = None,
) -> None:
    request_hints = hints or {}
    fingerprint = hashlib.sha1(
        json.dumps(
            [service, operation, arguments, region, request_hints], sort_keys=True
        ).encode("utf-8")
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
            hints=request_hints,
        )
    )

def node_context_requests(node: Node, default_region: str) -> list[ContextRequest]:
    requests: list[ContextRequest] = []
    kind = node.primary_kind
    name = node_name(node)
    region = node_region(node) or default_region
    if kind in {"RNR_LoadBalancer", "AWS_LoadBalancer"}:
        load_balancer_arn = node.arn
        if load_balancer_arn:
            add_context_request(requests, service="elbv2", operation="describe-load-balancers", arguments=["--load-balancer-arns", load_balancer_arn], reason="Confirm ALB scheme, type, VPC, subnets and security groups.", region=region)
            add_context_request(requests, service="elbv2", operation="describe-load-balancer-attributes", arguments=["--load-balancer-arn", load_balancer_arn], reason="Confirm ALB access logs, deletion protection, routing and security attributes.", region=region)
            add_context_request(requests, service="elbv2", operation="describe-tags", arguments=["--resource-arns", load_balancer_arn], reason="Collect ALB tags used for deterministic workload matching.", required=False, region=region)
            add_context_request(requests, service="elbv2", operation="describe-listeners", arguments=["--load-balancer-arn", load_balancer_arn], reason="Confirm listener protocols, ports and default actions.", region=region)
            add_context_request(requests, service="elbv2", operation="describe-target-groups", arguments=["--load-balancer-arn", load_balancer_arn], reason="Confirm target-group protocol, health check, target type and VPC.", region=region)
    elif kind == "RNR_WAFWebACL":
        waf_arn = node.arn or ""
        match = re.match(
            r"arn:[^:]+:wafv2:[^:]+:\d{12}:(?:regional|global)/webacl/([^/]+)/([^/]+)$",
            waf_arn,
        )
        if match:
            add_context_request(requests, service="wafv2", operation="get-web-acl", arguments=["--scope", "REGIONAL", "--name", match.group(1), "--id", match.group(2)], reason="Confirm WAF default action, rules and visibility configuration.", region=region)
            add_context_request(requests, service="wafv2", operation="list-resources-for-web-acl", arguments=["--web-acl-arn", waf_arn, "--resource-type", "APPLICATION_LOAD_BALANCER"], reason="Confirm WAF-to-ALB association.", required=False, region=region)
    elif kind == "RNR_SecurityGroup":
        group_id = str(node.properties.get("group_id") or "")
        if group_id:
            add_context_request(requests, service="ec2", operation="describe-security-groups", arguments=["--group-ids", group_id], reason="Confirm RNR security-group VPC and rule metadata.", region=region)
            add_context_request(requests, service="ec2", operation="describe-security-group-rules", arguments=["--filters", f"Name=group-id,Values={group_id}"], reason="Confirm normalized RNR security-group rules.", region=region)
    elif kind == "RNR_Subnet":
        subnet_id = str(node.properties.get("subnet_id") or "")
        if subnet_id:
            add_context_request(requests, service="ec2", operation="describe-subnets", arguments=["--subnet-ids", subnet_id], reason="Confirm RNR subnet VPC, CIDR, AZ and public-IP behavior.", region=region)
            add_context_request(requests, service="ec2", operation="describe-route-tables", arguments=["--filters", f"Name=association.subnet-id,Values={subnet_id}"], reason="Confirm routes applied to the RNR subnet.", region=region)
            add_context_request(requests, service="ec2", operation="describe-network-acls", arguments=["--filters", f"Name=association.subnet-id,Values={subnet_id}"], reason="Confirm NACL applied to the RNR subnet.", region=region)
    elif kind == "RNR_NetworkAcl":
        acl_id = str(node.properties.get("acl_id") or "")
        if acl_id:
            add_context_request(requests, service="ec2", operation="describe-network-acls", arguments=["--network-acl-ids", acl_id], reason="Confirm RNR network ACL entries, VPC and subnet associations.", region=region)
    elif kind == "RNR_AppEndpoint":
        workload_arn = str(node.properties.get("workload_arn") or "")
        if ":ecs:" in workload_arn and ":service/" in workload_arn:
            resource = workload_arn.split(":service/", 1)[-1]
            cluster = resource.split("/", 1)[0]
            add_context_request(requests, service="ecs", operation="describe-services", arguments=["--cluster", cluster, "--services", workload_arn, "--include", "TAGS"], reason="Resolve the endpoint's explicit ECS service binding.", region=region)
        elif ":lambda:" in workload_arn and ":function:" in workload_arn:
            add_context_request(requests, service="lambda", operation="get-function", arguments=["--function-name", workload_arn], reason="Resolve the endpoint's explicit Lambda binding.", region=region)
    elif kind == "AWS_ECSCluster":
        cluster = node.arn or name
        add_context_request(requests, service="ecs", operation="describe-clusters", arguments=["--clusters", cluster, "--include", "SETTINGS", "STATISTICS", "CONFIGURATIONS", "ATTACHMENTS"], reason="Confirm ECS cluster configuration.", region=region)
        add_context_request(requests, service="ecs", operation="list-services", arguments=["--cluster", cluster], reason="Enumerate services attached to the selected ECS cluster.", region=region)
        add_context_request(requests, service="ecs", operation="list-container-instances", arguments=["--cluster", cluster], reason="Enumerate EC2 container instances attached to the selected ECS cluster.", required=False, region=region)
    elif kind == "AWS_ECSService":
        service_arn = node.arn or name
        cluster = str(node.properties.get("cluster_arn") or node.properties.get("cluster_name") or "")
        if not cluster and ":service/" in service_arn:
            cluster = service_arn.split(":service/", 1)[-1].split("/", 1)[0]
        if cluster:
            add_context_request(requests, service="ecs", operation="describe-services", arguments=["--cluster", cluster, "--services", service_arn, "--include", "TAGS"], reason="Confirm ECS service task definition, deployment and network bindings.", region=region)
    elif kind == "AWS_ECSTask":
        task = node.arn or str(node.properties.get("task_id") or name)
        cluster = str(node.properties.get("cluster_arn") or node.properties.get("cluster_name") or "")
        if cluster:
            add_context_request(requests, service="ecs", operation="describe-tasks", arguments=["--cluster", cluster, "--tasks", task, "--include", "TAGS"], reason="Confirm ECS task definition, role and ENI bindings.", region=region)
    elif kind == "AWS_VPC":
        vpc_id = str(node.properties.get("vpc_id") or name)
        add_context_request(requests, service="ec2", operation="describe-vpcs", arguments=["--vpc-ids", vpc_id], reason="Confirm selected VPC configuration.", region=region)
    elif kind == "AWS_Subnet":
        subnet_id = str(node.properties.get("subnet_id") or name)
        add_context_request(requests, service="ec2", operation="describe-subnets", arguments=["--subnet-ids", subnet_id], reason="Confirm selected subnet configuration.", region=region)
        add_context_request(requests, service="ec2", operation="describe-route-tables", arguments=["--filters", f"Name=association.subnet-id,Values={subnet_id}"], reason="Confirm selected subnet routes.", region=region)
        add_context_request(requests, service="ec2", operation="describe-network-acls", arguments=["--filters", f"Name=association.subnet-id,Values={subnet_id}"], reason="Confirm selected subnet NACL.", region=region)
    elif kind == "AWS_SecurityGroup":
        group_id = str(node.properties.get("group_id") or name)
        add_context_request(requests, service="ec2", operation="describe-security-groups", arguments=["--group-ids", group_id], reason="Confirm selected security-group metadata.", region=region)
        add_context_request(requests, service="ec2", operation="describe-security-group-rules", arguments=["--filters", f"Name=group-id,Values={group_id}"], reason="Confirm selected security-group rules.", region=region)
    elif kind == "AWS_VPCEndpoint":
        endpoint_id = str(node.properties.get("vpc_endpoint_id") or node.properties.get("endpoint_id") or name)
        add_context_request(requests, service="ec2", operation="describe-vpc-endpoints", arguments=["--vpc-endpoint-ids", endpoint_id], reason="Confirm selected VPC endpoint service, subnets, policy and route bindings.", region=region)
    elif kind == "AWS_Database":
        database_arn = node.arn or ""
        if ":rds:" in database_arn and ":db:" in database_arn:
            identifier = database_arn.split(":db:", 1)[-1]
            add_context_request(requests, service="rds", operation="describe-db-instances", arguments=["--db-instance-identifier", identifier], reason="Confirm selected RDS instance configuration.", region=region)
    elif kind == "AWS_Secret":
        secret_id = node.arn or name
        add_context_request(requests, service="secretsmanager", operation="describe-secret", arguments=["--secret-id", secret_id], reason="Collect selected secret metadata only.", region=region)
        add_context_request(requests, service="secretsmanager", operation="get-resource-policy", arguments=["--secret-id", secret_id], reason="Collect selected secret resource policy without its value.", required=False, region=region)
    elif kind == "AWS_User":
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

def mirror_spec_context_requests(
    scenario: Scenario,
    nodes: dict[str, Node],
    mirror_spec: dict[str, Any] | None,
) -> list[ContextRequest]:
    workload_kinds = {
        "AWS_ECSCluster",
        "AWS_ECSService",
        "AWS_ECSTask",
        "RNR_AppEndpoint",
    }
    if not any(node.primary_kind in workload_kinds for node in nodes.values()):
        return []
    requests: list[ContextRequest] = []
    spec = mirror_spec or {}
    runtime = spec.get("selected_runtime_path", {})
    runtime = runtime if isinstance(runtime, dict) else {}
    task_ids = sorted(
        {
            str(value)
            for key, value in runtime.items()
            if str(key).endswith("_task_id") and value
        }
    )
    service_names = sorted(
        ({
            str(key).removesuffix("_task_id")
            for key, value in runtime.items()
            if str(key).endswith("_task_id") and value
        }
        | {
            str(node.properties.get("service"))
            for node in nodes.values()
            if node.primary_kind == "RNR_AppEndpoint"
            and node.properties.get("service")
            and str(node.properties.get("service")).lower() != "result"
        })
    )
    instance_ids = sorted(
        ({
            str(value)
            for key, value in runtime.items()
            if str(key).endswith("_instance_id") and value
        }
        | {
            str(node.properties.get("instance_id"))
            for node in nodes.values()
            if node.primary_kind == "AWS_EC2Instance"
            and node.properties.get("instance_id")
        })
    )
    project = next(
        (
            str(node.properties.get("project"))
            for node in nodes.values()
            if node.primary_kind == "RNR_Environment"
            and node.properties.get("project")
        ),
        str(spec.get("project") or ""),
    )
    add_context_request(
        requests,
        service="ecs",
        operation="list-clusters",
        arguments=[],
        reason="Discover the ECS cluster containing the selected runtime task IDs.",
        region=scenario.region,
        hints={"task_ids": task_ids, "service_names": service_names},
    )
    if project:
        add_context_request(
            requests,
            service="resourcegroupstaggingapi",
            operation="get-resources",
            arguments=[
                "--tag-filters",
                f"Key=Project,Values={project}",
                "--resource-type-filters",
                "ecs:service",
                "rds:db",
                "secretsmanager:secret",
                "ecr:repository",
            ],
            reason="Discover only resources carrying the graph's project tag.",
            required=False,
            region=scenario.region,
            hints={"project": project},
        )
    if instance_ids:
        add_context_request(
            requests,
            service="autoscaling",
            operation="describe-auto-scaling-instances",
            arguments=["--instance-ids", *instance_ids],
            reason="Confirm whether the selected ECS node is managed by an Auto Scaling group.",
            required=False,
            region=scenario.region,
        )
    return requests


def context_plan(
    scenario: Scenario,
    nodes: dict[str, Node],
    edges: list[Edge],
    mirror_spec: dict[str, Any] | None = None,
) -> list[ContextRequest]:
    requests: list[ContextRequest] = []
    for node_id in scenario.node_ids:
        requests.extend(node_context_requests(nodes[node_id], scenario.region))
    requests.extend(mirror_spec_context_requests(scenario, nodes, mirror_spec))

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
    read_only_prefixes = (
        "get-",
        "list-",
        "describe-",
        "head-",
        "simulate-",
        "validate-",
        "batch-get-",
    )
    if request.mutating or not request.operation.startswith(read_only_prefixes):
        raise PipelineError(
            f"context collector rejected a non-read-only operation: "
            f"{request.service}:{request.operation}"
        )
    if request.service == "secretsmanager" and request.operation == "get-secret-value":
        raise PipelineError("context collector never retrieves secret values")
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


def request_argument(request: ContextRequest, flag: str) -> str | None:
    try:
        return request.arguments[request.arguments.index(flag) + 1]
    except (ValueError, IndexError):
        return None


def chunks(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def ecr_image_reference(value: str) -> dict[str, str] | None:
    match = re.match(
        r"^(?P<registry>\d{12})\.dkr\.ecr\.(?P<region>[^.]+)\.amazonaws\.com/"
        r"(?P<repository>[^@:]+(?:/[^@:]+)*)(?:(?::(?P<tag>[^@]+))|(?:@(?P<digest>sha256:[0-9a-fA-F]+)))?$",
        value,
    )
    return match.groupdict() if match else None


def nested_values(value: Any, key: str) -> Iterable[Any]:
    if isinstance(value, dict):
        for current_key, current_value in value.items():
            if current_key == key:
                yield current_value
            yield from nested_values(current_value, key)
    elif isinstance(value, list):
        for item in value:
            yield from nested_values(item, key)

def expand_context_response(
    request: ContextRequest, response: dict[str, Any]
) -> list[ContextRequest]:
    region = request.region or "us-east-1"
    if request.service == "ecs" and request.operation == "list-clusters":
        requests: list[ContextRequest] = []
        task_ids = [str(value) for value in request.hints.get("task_ids", [])]
        service_names = [
            str(value) for value in request.hints.get("service_names", [])
        ]
        for cluster_arn in response.get("clusterArns", []):
            cluster = str(cluster_arn)
            add_context_request(
                requests,
                service="ecs",
                operation="describe-clusters",
                arguments=["--clusters", cluster, "--include", "SETTINGS", "STATISTICS", "CONFIGURATIONS", "ATTACHMENTS"],
                reason="Confirm ECS cluster settings and capacity providers.",
                region=region,
            )
            if task_ids:
                add_context_request(
                    requests,
                    service="ecs",
                    operation="describe-tasks",
                    arguments=["--cluster", cluster, "--tasks", *task_ids, "--include", "TAGS"],
                    reason="Locate selected mirror-spec tasks in this ECS cluster.",
                    required=False,
                    region=region,
                    hints={"service_names": service_names},
                )
            add_context_request(
                requests,
                service="ecs",
                operation="list-services",
                arguments=["--cluster", cluster],
                reason="Enumerate ECS services so endpoint service names can be bound to workloads.",
                required=False,
                region=region,
                hints={"service_names": service_names},
            )
            add_context_request(
                requests,
                service="ecs",
                operation="list-container-instances",
                arguments=["--cluster", cluster],
                reason="Enumerate ECS container instances for the selected EC2 launch-type node.",
                required=False,
                region=region,
            )
        return requests
    if request.service == "ecs" and request.operation == "list-services":
        requests = []
        cluster = request_argument(request, "--cluster") or ""
        wanted = {
            value.lower() for value in request.hints.get("service_names", [])
        }
        service_arns = [str(value) for value in response.get("serviceArns", [])]
        preferred = [
            arn
            for arn in service_arns
            if not wanted
            or any(name in arn.rsplit("/", 1)[-1].lower() for name in wanted)
        ]
        for batch in chunks(preferred or service_arns, 10):
            add_context_request(
                requests,
                service="ecs",
                operation="describe-services",
                arguments=["--cluster", cluster, "--services", *batch, "--include", "TAGS"],
                reason="Resolve ECS services to task definitions, target groups and network configuration.",
                required=False,
                region=region,
            )
        return requests
    if request.service == "ecs" and request.operation == "list-container-instances":
        arns = [str(value) for value in response.get("containerInstanceArns", [])]
        if not arns:
            return []
        return [
            ContextRequest(
                request_id="ctx-" + hashlib.sha1(("ecs-container-instances" + "\n".join(arns)).encode()).hexdigest()[:10],
                service="ecs",
                operation="describe-container-instances",
                arguments=["--cluster", request_argument(request, "--cluster") or "", "--container-instances", *arns, "--include", "TAGS", "CONTAINER_INSTANCE_HEALTH"],
                reason="Resolve ECS container instances to EC2 instance IDs.",
                required=False,
                region=region,
            )
        ]
    if request.service == "ecs" and request.operation == "describe-container-instances":
        requests = []
        instance_ids = sorted(
            {
                str(value.get("ec2InstanceId"))
                for value in response.get("containerInstances", [])
                if value.get("ec2InstanceId")
            }
        )
        if instance_ids:
            add_context_request(requests, service="ec2", operation="describe-instances", arguments=["--instance-ids", *instance_ids], reason="Collect EC2 configuration for ECS container instances.", region=region)
        return requests
    if request.service == "ecs" and request.operation == "describe-tasks":
        requests = []
        cluster = request_argument(request, "--cluster") or ""
        task_definitions = sorted(
            {
                str(task.get("taskDefinitionArn"))
                for task in response.get("tasks", [])
                if task.get("taskDefinitionArn")
            }
        )
        for task_definition in task_definitions:
            add_context_request(requests, service="ecs", operation="describe-task-definition", arguments=["--task-definition", task_definition, "--include", "TAGS"], reason="Collect the selected task's container image, ports, roles, volumes and runtime settings.", region=region)
        container_instances = sorted(
            {
                str(task.get("containerInstanceArn"))
                for task in response.get("tasks", [])
                if task.get("containerInstanceArn")
            }
        )
        if container_instances:
            add_context_request(requests, service="ecs", operation="describe-container-instances", arguments=["--cluster", cluster, "--container-instances", *container_instances, "--include", "TAGS", "CONTAINER_INSTANCE_HEALTH"], reason="Resolve selected tasks to their EC2 container instances.", region=region)
        eni_ids = sorted(
            {
                str(detail.get("value"))
                for task in response.get("tasks", [])
                for attachment in task.get("attachments", [])
                for detail in attachment.get("details", [])
                if detail.get("name") == "networkInterfaceId" and detail.get("value")
            }
        )
        if eni_ids:
            add_context_request(requests, service="ec2", operation="describe-network-interfaces", arguments=["--network-interface-ids", *eni_ids], reason="Collect task ENI subnet, IP and security-group bindings.", region=region)
        return requests
    if request.service == "ecs" and request.operation == "describe-services":
        requests = []
        for service in response.get("services", []):
            task_definition = str(service.get("taskDefinition") or "")
            if task_definition:
                add_context_request(requests, service="ecs", operation="describe-task-definition", arguments=["--task-definition", task_definition, "--include", "TAGS"], reason="Collect ECS service task-definition runtime settings.", region=region)
            for binding in service.get("loadBalancers", []):
                target_group = str(binding.get("targetGroupArn") or "")
                if target_group:
                    add_context_request(requests, service="elbv2", operation="describe-target-groups", arguments=["--target-group-arns", target_group], reason="Collect ECS service target-group configuration.", region=region)
                    add_context_request(requests, service="elbv2", operation="describe-target-health", arguments=["--target-group-arn", target_group], reason="Confirm ECS service target registration and health.", region=region)
            network = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
            requests.extend(
                discovered_network_requests(
                    vpc_ids=[],
                    subnet_ids=[str(value) for value in network.get("subnets", [])],
                    security_group_ids=[str(value) for value in network.get("securityGroups", [])],
                    region=region,
                    reason_prefix="ECS service dependency expansion",
                )
            )
        return requests
    if request.service == "ecs" and request.operation == "describe-task-definition":
        requests = []
        task_definition = response.get("taskDefinition", {})
        for container in task_definition.get("containerDefinitions", []):
            image = str(container.get("image") or "")
            parsed = ecr_image_reference(image)
            if parsed:
                image_selector = (
                    f"imageDigest={parsed['digest']}"
                    if parsed.get("digest")
                    else f"imageTag={parsed.get('tag') or 'latest'}"
                )
                common = [
                    "--registry-id", parsed["registry"],
                    "--repository-name", parsed["repository"],
                    "--image-ids", image_selector,
                ]
                add_context_request(requests, service="ecr", operation="describe-images", arguments=common, reason="Resolve the task image tag to an immutable digest.", region=parsed["region"])
                add_context_request(requests, service="ecr", operation="batch-get-image", arguments=common, reason="Collect the OCI image manifest without copying image layers.", region=parsed["region"])
            for secret in container.get("secrets", []):
                value_from = str(secret.get("valueFrom") or "")
                if ":secretsmanager:" in value_from:
                    add_context_request(requests, service="secretsmanager", operation="describe-secret", arguments=["--secret-id", value_from], reason="Collect secret metadata only; never retrieve its value.", required=False, region=region)
                    add_context_request(requests, service="secretsmanager", operation="get-resource-policy", arguments=["--secret-id", value_from], reason="Collect the secret resource policy without retrieving its value.", required=False, region=region)
                elif ":ssm:" in value_from:
                    parameter_name = value_from.split(":parameter", 1)[-1]
                    add_context_request(requests, service="ssm", operation="describe-parameters", arguments=["--parameter-filters", f"Key=Name,Option=Equals,Values={parameter_name}"], reason="Collect injected SSM parameter metadata only.", required=False, region=region)
        for role_key in ("taskRoleArn", "executionRoleArn"):
            role_arn = str(task_definition.get(role_key) or "")
            if role_arn:
                add_context_request(requests, service="iam", operation="get-role", arguments=["--role-name", role_arn.rsplit("/", 1)[-1]], reason=f"Confirm ECS {role_key} trust and metadata.")
        return requests
    if (
        request.service == "resourcegroupstaggingapi"
        and request.operation == "get-resources"
    ):
        requests = []
        for mapping in response.get("ResourceTagMappingList", []):
            arn = str(mapping.get("ResourceARN") or "")
            if ":ecs:" in arn and ":service/" in arn:
                resource = arn.split(":service/", 1)[-1]
                cluster = resource.split("/", 1)[0]
                add_context_request(requests, service="ecs", operation="describe-services", arguments=["--cluster", cluster, "--services", arn, "--include", "TAGS"], reason="Collect the project-tagged ECS service configuration.", required=False, region=region)
            elif ":rds:" in arn and ":db:" in arn:
                identifier = arn.split(":db:", 1)[-1]
                add_context_request(requests, service="rds", operation="describe-db-instances", arguments=["--db-instance-identifier", identifier], reason="Collect the project-tagged RDS instance configuration.", required=False, region=region)
            elif ":secretsmanager:" in arn and ":secret:" in arn:
                add_context_request(requests, service="secretsmanager", operation="describe-secret", arguments=["--secret-id", arn], reason="Collect project-tagged secret metadata only.", required=False, region=region)
                add_context_request(requests, service="secretsmanager", operation="get-resource-policy", arguments=["--secret-id", arn], reason="Collect project-tagged secret policy without retrieving its value.", required=False, region=region)
            elif ":ecr:" in arn and ":repository/" in arn:
                repository = arn.split(":repository/", 1)[-1]
                add_context_request(requests, service="ecr", operation="describe-repositories", arguments=["--repository-names", repository], reason="Collect project-tagged ECR repository settings and policy dependencies.", required=False, region=region)
                add_context_request(requests, service="ecr", operation="get-repository-policy", arguments=["--repository-name", repository], reason="Confirm whether a mirror account can pull the source image.", required=False, region=region)
        return requests
    if request.service == "rds" and request.operation == "describe-db-instances":
        requests = []
        for instance in response.get("DBInstances", []):
            identifier = str(instance.get("DBInstanceIdentifier") or "")
            subnet_group = instance.get("DBSubnetGroup", {}) or {}
            subnet_group_name = str(subnet_group.get("DBSubnetGroupName") or "")
            if subnet_group_name:
                add_context_request(requests, service="rds", operation="describe-db-subnet-groups", arguments=["--db-subnet-group-name", subnet_group_name], reason="Collect RDS subnet-group VPC and subnet membership.", region=region)
            for parameter_group in instance.get("DBParameterGroups", []):
                name = str(parameter_group.get("DBParameterGroupName") or "")
                if name:
                    add_context_request(requests, service="rds", operation="describe-db-parameters", arguments=["--db-parameter-group-name", name], reason="Collect effective RDS parameter-group settings.", required=False, region=region)
            if identifier:
                add_context_request(requests, service="rds", operation="describe-db-snapshots", arguments=["--db-instance-identifier", identifier, "--snapshot-type", "manual"], reason="Discover approved manual snapshots for functional mirror restoration.", required=False, region=region)
                add_context_request(requests, service="rds", operation="list-tags-for-resource", arguments=["--resource-name", str(instance.get("DBInstanceArn") or "")], reason="Confirm RDS data-classification and project tags.", required=False, region=region)
            requests.extend(
                discovered_network_requests(
                    vpc_ids=[str(subnet_group.get("VpcId") or "")],
                    subnet_ids=[
                        str(value.get("SubnetIdentifier") or "")
                        for value in subnet_group.get("Subnets", [])
                    ],
                    security_group_ids=[
                        str(value.get("VpcSecurityGroupId") or "")
                        for value in instance.get("VpcSecurityGroups", [])
                    ],
                    region=region,
                    reason_prefix="RDS dependency expansion",
                )
            )
            kms_key_id = str(instance.get("KmsKeyId") or "")
            if kms_key_id:
                add_context_request(requests, service="kms", operation="describe-key", arguments=["--key-id", kms_key_id], reason="Collect RDS encryption-key metadata; key material is never copied.", required=False, region=region)
            secret_arn = str((instance.get("MasterUserSecret") or {}).get("SecretArn") or "")
            if secret_arn:
                add_context_request(requests, service="secretsmanager", operation="describe-secret", arguments=["--secret-id", secret_arn], reason="Collect RDS managed-secret metadata only.", required=False, region=region)
        return requests
    if request.service == "secretsmanager" and request.operation == "describe-secret":
        requests = []
        kms_key_id = str(response.get("KmsKeyId") or "")
        if kms_key_id:
            add_context_request(requests, service="kms", operation="describe-key", arguments=["--key-id", kms_key_id], reason="Collect secret KMS-key metadata; key material is never copied.", required=False, region=region)
        return requests
    if request.service == "autoscaling" and request.operation == "describe-auto-scaling-instances":
        requests = []
        groups = sorted(
            {
                str(value.get("AutoScalingGroupName"))
                for value in response.get("AutoScalingInstances", [])
                if value.get("AutoScalingGroupName")
            }
        )
        if groups:
            add_context_request(requests, service="autoscaling", operation="describe-auto-scaling-groups", arguments=["--auto-scaling-group-names", *groups], reason="Collect ECS node Auto Scaling capacity and launch-template bindings.", required=False, region=region)
        return requests
    if request.service == "autoscaling" and request.operation == "describe-auto-scaling-groups":
        requests = []
        for group in response.get("AutoScalingGroups", []):
            template = group.get("LaunchTemplate") or {}
            template_id = str(template.get("LaunchTemplateId") or "")
            version = str(template.get("Version") or "$Default")
            if template_id:
                add_context_request(requests, service="ec2", operation="describe-launch-template-versions", arguments=["--launch-template-id", template_id, "--versions", version], reason="Collect the ECS node launch-template AMI, instance profile, user data and network settings.", region=region)
        return requests
    if request.service == "ec2" and request.operation == "describe-instances":
        instances = [
            instance
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
        requests = discovered_network_requests(
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
        volume_ids = sorted(
            {
                str(mapping.get("Ebs", {}).get("VolumeId"))
                for item in instances
                for mapping in item.get("BlockDeviceMappings", [])
                if mapping.get("Ebs", {}).get("VolumeId")
            }
        )
        if volume_ids:
            add_context_request(requests, service="ec2", operation="describe-volumes", arguments=["--volume-ids", *volume_ids], reason="Collect EBS type, size, encryption and snapshot lineage.", region=region)
        for item in instances:
            template = item.get("LaunchTemplate") or {}
            template_id = str(template.get("LaunchTemplateId") or "")
            version = str(template.get("Version") or "$Default")
            if template_id:
                add_context_request(requests, service="ec2", operation="describe-launch-template-versions", arguments=["--launch-template-id", template_id, "--versions", version], reason="Collect launch-template settings for the selected ECS node.", required=False, region=region)
        return requests
    if request.service == "ec2" and request.operation == "describe-network-interfaces":
        interfaces = response.get("NetworkInterfaces", [])
        return discovered_network_requests(
            vpc_ids=[str(item.get("VpcId", "")) for item in interfaces],
            subnet_ids=[str(item.get("SubnetId", "")) for item in interfaces],
            security_group_ids=[
                str(group.get("GroupId", ""))
                for item in interfaces
                for group in item.get("Groups", [])
            ],
            region=region,
            reason_prefix="ENI dependency expansion",
        )
    if request.service == "ec2" and request.operation == "describe-security-groups":
        groups = response.get("SecurityGroups", [])
        return discovered_network_requests(
            vpc_ids=[str(item.get("VpcId", "")) for item in groups],
            subnet_ids=[],
            security_group_ids=[],
            region=region,
            reason_prefix="Security-group dependency expansion",
        )
    if request.service == "elbv2" and request.operation == "describe-load-balancers":
        load_balancers = response.get("LoadBalancers", [])
        return discovered_network_requests(
            vpc_ids=[str(item.get("VpcId", "")) for item in load_balancers],
            subnet_ids=[
                str(zone.get("SubnetId", ""))
                for item in load_balancers
                for zone in item.get("AvailabilityZones", [])
            ],
            security_group_ids=[
                str(group_id)
                for item in load_balancers
                for group_id in item.get("SecurityGroups", [])
            ],
            region=region,
            reason_prefix="ALB dependency expansion",
        )
    if request.service == "elbv2" and request.operation == "describe-listeners":
        requests: list[ContextRequest] = []
        for listener in response.get("Listeners", []):
            listener_arn = str(listener.get("ListenerArn") or "")
            if listener_arn:
                add_context_request(
                    requests,
                    service="elbv2",
                    operation="describe-rules",
                    arguments=["--listener-arn", listener_arn],
                    reason="Confirm listener routing rules and conditions.",
                    region=region,
                )
        return requests
    if request.service == "elbv2" and request.operation == "describe-target-groups":
        requests = []
        for target_group in response.get("TargetGroups", []):
            target_group_arn = str(target_group.get("TargetGroupArn") or "")
            if target_group_arn:
                add_context_request(
                    requests,
                    service="elbv2",
                    operation="describe-target-health",
                    arguments=["--target-group-arn", target_group_arn],
                    reason="Confirm target identities, ports and health state.",
                    region=region,
                )
                add_context_request(
                    requests,
                    service="elbv2",
                    operation="describe-target-group-attributes",
                    arguments=["--target-group-arn", target_group_arn],
                    reason="Collect target-group routing, deregistration and stickiness attributes.",
                    required=False,
                    region=region,
                )
        return requests
    if request.service == "elbv2" and request.operation == "describe-target-health":
        requests = []
        instance_ids: list[str] = []
        private_ips: list[str] = []
        for value in response.get("TargetHealthDescriptions", []):
            target_id = str((value.get("Target") or {}).get("Id") or "")
            if target_id.startswith("i-"):
                instance_ids.append(target_id)
            elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", target_id):
                private_ips.append(target_id)
            elif target_id.startswith("arn:") and ":lambda:" in target_id:
                add_context_request(requests, service="lambda", operation="get-function", arguments=["--function-name", target_id], reason="Collect Lambda target configuration.", required=False, region=region)
        if instance_ids:
            add_context_request(requests, service="ec2", operation="describe-instances", arguments=["--instance-ids", *sorted(set(instance_ids))], reason="Resolve instance-type target-group members.", region=region)
        for private_ip in sorted(set(private_ips)):
            add_context_request(requests, service="ec2", operation="describe-network-interfaces", arguments=["--filters", f"Name=addresses.private-ip-address,Values={private_ip}"], reason="Resolve IP-type target-group members to task ENIs.", required=False, region=region)
        return requests
    if request.service == "wafv2" and request.operation == "get-web-acl":
        requests = []
        for statement in nested_values(response.get("WebACL", {}), "IPSetReferenceStatement"):
            arn = str(statement.get("ARN") or "") if isinstance(statement, dict) else ""
            match = re.match(
                r"arn:[^:]+:wafv2:[^:]+:\d{12}:(regional|global)/ipset/([^/]+)/([^/]+)$",
                arn,
            )
            if match:
                add_context_request(requests, service="wafv2", operation="get-ip-set", arguments=["--scope", "REGIONAL" if match.group(1) == "regional" else "CLOUDFRONT", "--name", match.group(2), "--id", match.group(3)], reason="Collect WAF IP-set addresses referenced by the selected Web ACL.", required=False, region=region)
        return requests
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
                parsed_response = json.loads(completed.stdout or "{}")
                entry["response"] = sanitize_context_response(
                    request, parsed_response
                )
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


def sanitize_context_response(
    request: ContextRequest, response: dict[str, Any]
) -> dict[str, Any]:
    """Remove credential-like values before Context evidence is persisted."""
    sanitized = json.loads(json.dumps(response, default=str))
    if request.service == "ecs" and request.operation == "describe-task-definition":
        definition = sanitized.get("taskDefinition", {})
        for container in definition.get("containerDefinitions", []):
            for item in container.get("environment", []):
                key = str(item.get("name") or "")
                if re.search(
                    r"(?:secret|password|passwd|token|api.?key|private.?key)",
                    key,
                    re.I,
                ):
                    item["value"] = "REDACTED_SYNTHETIC_REQUIRED"
    if request.service == "ec2" and request.operation in {
        "describe-instance-attribute",
        "describe-launch-template-versions",
    }:
        if "UserData" in sanitized:
            value = str((sanitized.get("UserData") or {}).get("Value") or "")
            sanitized["UserData"] = {
                "Redacted": True,
                "Sha256": sha256_bytes(value.encode("utf-8")) if value else None,
            }
        for version in sanitized.get("LaunchTemplateVersions", []):
            data = version.get("LaunchTemplateData", {})
            if data.get("UserData"):
                value = str(data["UserData"])
                data["UserData"] = {
                    "Redacted": True,
                    "Sha256": sha256_bytes(value.encode("utf-8")),
                }
    if request.service == "lambda" and request.operation == "get-function":
        code = sanitized.get("Code", {})
        if code.get("Location"):
            code["Location"] = "REDACTED_EPHEMERAL_DOWNLOAD_URL"
    return sanitized


def context_inventory(evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Build a compact, secret-free inventory from collected read-only responses."""
    inventory: dict[str, Any] = {
        "ecs_clusters": [],
        "ecs_services": [],
        "ecs_tasks": [],
        "ecs_task_definitions": [],
        "ecr_images": [],
        "load_balancers": [],
        "listeners": [],
        "target_groups": [],
        "rds_instances": [],
        "rds_snapshots": [],
        "secrets_metadata": [],
        "safety": {
            "secret_values_collected": False,
            "ssm_values_collected": False,
            "mutating_operations_executed": False,
        },
    }
    if not evidence:
        return inventory
    for item in evidence.get("results", []):
        if item.get("status") != "COLLECTED":
            continue
        operation = item.get("request", {}).get("operation")
        response = item.get("response", {})
        if operation == "describe-clusters":
            inventory["ecs_clusters"].extend(response.get("clusters", []))
        elif operation == "describe-services":
            inventory["ecs_services"].extend(response.get("services", []))
        elif operation == "describe-tasks":
            inventory["ecs_tasks"].extend(response.get("tasks", []))
        elif operation == "describe-task-definition" and response.get("taskDefinition"):
            inventory["ecs_task_definitions"].append(response["taskDefinition"])
        elif operation in {"describe-images", "batch-get-image"}:
            images = response.get("imageDetails", response.get("images", []))
            inventory["ecr_images"].extend(images)
        elif operation == "describe-load-balancers":
            inventory["load_balancers"].extend(response.get("LoadBalancers", []))
        elif operation == "describe-listeners":
            inventory["listeners"].extend(response.get("Listeners", []))
        elif operation == "describe-target-groups":
            inventory["target_groups"].extend(response.get("TargetGroups", []))
        elif operation == "describe-db-instances":
            inventory["rds_instances"].extend(response.get("DBInstances", []))
        elif operation == "describe-db-snapshots":
            inventory["rds_snapshots"].extend(response.get("DBSnapshots", []))
        elif operation == "describe-secret":
            inventory["secrets_metadata"].append(
                {
                    key: response.get(key)
                    for key in (
                        "ARN",
                        "Name",
                        "Description",
                        "KmsKeyId",
                        "RotationEnabled",
                        "RotationLambdaARN",
                        "Tags",
                    )
                    if key in response
                }
            )
    for key, values in inventory.items():
        if not isinstance(values, list):
            continue
        unique: dict[str, Any] = {}
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                unique[str(index)] = value
                continue
            identity = next(
                (
                    str(value.get(field))
                    for field in (
                        "clusterArn",
                        "serviceArn",
                        "taskArn",
                        "taskDefinitionArn",
                        "imageDigest",
                        "LoadBalancerArn",
                        "ListenerArn",
                        "TargetGroupArn",
                        "DBInstanceArn",
                        "DBSnapshotArn",
                        "ARN",
                    )
                    if value.get(field)
                ),
                json.dumps(value, sort_keys=True, default=str),
            )
            unique[identity] = value
        inventory[key] = list(unique.values())
    return inventory

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


def resolved_ecr_image(
    evidence: dict[str, Any] | None, source_image: str
) -> str:
    parsed = ecr_image_reference(source_image)
    if not parsed or not evidence:
        return source_image
    repository = parsed["repository"]
    registry = parsed["registry"]
    for item in evidence.get("results", []):
        if item.get("status") != "COLLECTED":
            continue
        request = item.get("request", {})
        if request.get("service") != "ecr":
            continue
        arguments = request.get("arguments", [])
        try:
            requested_repository = arguments[arguments.index("--repository-name") + 1]
        except (ValueError, IndexError):
            continue
        if requested_repository != repository:
            continue
        response = item.get("response", {})
        images = response.get("images", response.get("imageDetails", []))
        for image in images:
            image_id = image.get("imageId", image)
            digest = str(image_id.get("imageDigest") or "")
            if digest:
                return (
                    f"{registry}.dkr.ecr.{parsed['region']}.amazonaws.com/"
                    f"{repository}@{digest}"
                )
    return source_image


def render_integrated_services_from_context(
    *,
    scenario: Scenario,
    nodes: dict[str, Node],
    addresses: dict[str, str],
    selected_edges: list[Edge],
    context_evidence: dict[str, Any] | None,
    mirror_spec: dict[str, Any] | None,
    network_subnet_refs: dict[str, str],
    network_sg_refs: dict[str, str],
) -> tuple[str, list[dict[str, Any]], list[str], str | None]:
    if not context_evidence:
        return "", [], [], None
    inventory = context_inventory(context_evidence)
    services = inventory["ecs_services"]
    task_definitions = {
        str(value.get("taskDefinitionArn")): value
        for value in inventory["ecs_task_definitions"]
        if value.get("taskDefinitionArn")
    }
    runtime = (mirror_spec or {}).get("selected_runtime_path", {})
    runtime = runtime if isinstance(runtime, dict) else {}
    wanted_services = {
        str(key).removesuffix("_task_id").lower()
        for key, value in runtime.items()
        if str(key).endswith("_task_id") and value
    }
    wanted_services.update(
        {
            str(node.properties.get("service")).lower()
            for node in nodes.values()
            if node.primary_kind == "RNR_AppEndpoint"
            and node.properties.get("service")
            and str(node.properties.get("service")).lower() != "result"
        }
    )
    selected_services = [
        value
        for value in services
        if not wanted_services
        or any(
            name in str(value.get("serviceName") or "").lower()
            for name in wanted_services
        )
    ]
    if not selected_services or not task_definitions:
        return "", [], ["ECS_RUNTIME_CONTEXT_REQUIRED"], None

    blocks: list[str] = []
    coverage: list[dict[str, Any]] = []
    blockers: list[str] = []
    cluster_arns = sorted(
        {
            str(value.get("clusterArn"))
            for value in selected_services
            if value.get("clusterArn")
        }
    )
    cluster_refs: dict[str, str] = {}
    for cluster_arn in cluster_arns:
        address = network_tf_address("ecs_cluster", cluster_arn.rsplit("/", 1)[-1])
        blocks.append(f'''
resource "aws_ecs_cluster" "{address}" {{
  name = substr("${{local.prefix}}-{address}", 0, 255)
}}
''')
        cluster_refs[cluster_arn] = f"aws_ecs_cluster.{address}.id"
        coverage.append({"resource": cluster_arn, "status": "CONTEXT_REPRODUCIBLE", "kind": "ECS_CLUSTER"})
    primary_cluster_ref = next(iter(cluster_refs.values()), None)

    blocks.append('''
resource "aws_iam_role" "mirror_ecs_execution" {
  name = substr("${local.prefix}-ecs-execution", 0, 64)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "mirror_ecs_execution" {
  role       = aws_iam_role.mirror_ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
''')

    role_refs = {
        node.arn: f"aws_iam_role.{addresses[node_id]}.arn"
        for node_id, node in nodes.items()
        if node_id in addresses and node.primary_kind == "AWS_Role" and node.arn
    }
    task_definition_refs: dict[str, str] = {}
    for source_arn, definition in task_definitions.items():
        if source_arn not in {
            str(service.get("taskDefinition")) for service in selected_services
        }:
            continue
        family = str(definition.get("family") or source_arn.rsplit("/", 1)[-1].split(":", 1)[0])
        address = network_tf_address("task", family)
        containers: list[dict[str, Any]] = []
        for source_container in definition.get("containerDefinitions", []):
            container: dict[str, Any] = {}
            for key in (
                "name",
                "cpu",
                "memory",
                "memoryReservation",
                "essential",
                "portMappings",
                "command",
                "entryPoint",
                "healthCheck",
                "workingDirectory",
                "readonlyRootFilesystem",
                "user",
            ):
                if key in source_container:
                    container[key] = source_container[key]
            source_image = str(source_container.get("image") or "")
            container["image"] = resolved_ecr_image(context_evidence, source_image)
            environment: list[dict[str, str]] = []
            for item in source_container.get("environment", []):
                key = str(item.get("name") or "")
                value = str(item.get("value") or "")
                if re.search(r"(?:secret|password|passwd|token|api.?key|private.?key)", key, re.I):
                    value = "SYNTHETIC_REPLACE_ME"
                    blockers.append(f"SENSITIVE_ENV_REPLACED:{family}:{key}")
                environment.append({"name": key, "value": value})
            if environment:
                container["environment"] = environment
            if source_container.get("secrets"):
                blockers.append(f"TASK_SECRET_CONTRACT_REQUIRED:{family}")
            containers.append(container)
            if "@sha256:" not in container["image"]:
                blockers.append(f"IMMUTABLE_IMAGE_DIGEST_REQUIRED:{family}:{container.get('name', 'container')}")
        task_role = role_refs.get(str(definition.get("taskRoleArn") or ""))
        if definition.get("taskRoleArn") and not task_role:
            blockers.append(f"TASK_ROLE_MAPPING_REQUIRED:{family}")
        if definition.get("volumes"):
            blockers.append(f"TASK_VOLUME_ADAPTER_REQUIRED:{family}")
        optional_lines: list[str] = []
        if definition.get("cpu") is not None:
            optional_lines.append(f"  cpu                      = {json.dumps(str(definition['cpu']))}")
        if definition.get("memory") is not None:
            optional_lines.append(f"  memory                   = {json.dumps(str(definition['memory']))}")
        if task_role:
            optional_lines.append(f"  task_role_arn            = {task_role}")
        requires = definition.get("requiresCompatibilities") or ["EC2"]
        blocks.append(f'''
resource "aws_ecs_task_definition" "{address}" {{
  family                   = substr("${{local.prefix}}-{address}", 0, 255)
  network_mode             = {json.dumps(str(definition.get('networkMode') or 'awsvpc'))}
  requires_compatibilities = {json.dumps(requires)}
  execution_role_arn       = aws_iam_role.mirror_ecs_execution.arn
{chr(10).join(optional_lines)}
  container_definitions    = jsonencode({json.dumps(containers, ensure_ascii=False)})
}}
''')
        task_definition_refs[source_arn] = f"aws_ecs_task_definition.{address}.arn"
        coverage.append({"resource": source_arn, "status": "SEMANTIC_MIRROR", "kind": "ECS_TASK_DEFINITION"})

    target_group_refs: dict[str, str] = {}
    load_balancer_refs: dict[str, str] = {}
    network_model = network_model_from_context(context_evidence)
    selected_lb_arns = {
        node.arn
        for node in nodes.values()
        if node.primary_kind == "RNR_LoadBalancer" and node.arn
    }
    for load_balancer in inventory["load_balancers"]:
        source_arn = str(load_balancer.get("LoadBalancerArn") or "")
        if selected_lb_arns and source_arn not in selected_lb_arns:
            continue
        address = network_tf_address("lb", source_arn.rsplit("/", 2)[-2] if source_arn else "mirror")
        subnet_values = [
            network_subnet_refs.get(str(zone.get("SubnetId") or ""))
            for zone in load_balancer.get("AvailabilityZones", [])
        ]
        subnet_values = [value for value in subnet_values if value]
        group_values = [
            network_sg_refs.get(str(group_id))
            for group_id in load_balancer.get("SecurityGroups", [])
        ]
        group_values = [value for value in group_values if value]
        if len(subnet_values) < 2 or not group_values:
            blockers.append("ALB_NETWORK_CONTEXT_REQUIRED")
            continue
        blocks.append(f'''
resource "aws_lb" "{address}" {{
  name               = substr("${{local.prefix}}-alb", 0, 32)
  internal           = {str(str(load_balancer.get('Scheme')) == 'internal').lower()}
  load_balancer_type = {json.dumps(str(load_balancer.get('Type') or 'application'))}
  subnets            = [{', '.join(subnet_values)}]
  security_groups    = [{', '.join(group_values)}]
}}
''')
        load_balancer_refs[source_arn] = f"aws_lb.{address}.arn"
        coverage.append({"resource": source_arn, "status": "CONTEXT_REPRODUCIBLE", "kind": "ALB"})
    for target_group in inventory["target_groups"]:
        source_arn = str(target_group.get("TargetGroupArn") or "")
        vpc_id = str(target_group.get("VpcId") or "")
        if vpc_id not in network_model["vpcs"]:
            blockers.append(f"TARGET_GROUP_VPC_CONTEXT_REQUIRED:{source_arn}")
            continue
        address = network_tf_address("tg", str(target_group.get("TargetGroupName") or source_arn))
        blocks.append(f'''
resource "aws_lb_target_group" "{address}" {{
  name        = substr("${{local.prefix}}-{address}", 0, 32)
  port        = {int(target_group.get('Port') or 80)}
  protocol    = {json.dumps(str(target_group.get('Protocol') or 'HTTP'))}
  target_type = {json.dumps(str(target_group.get('TargetType') or 'ip'))}
  vpc_id      = aws_vpc.{network_tf_address('vpc', vpc_id)}.id

  health_check {{
    enabled             = {str(bool(target_group.get('HealthCheckEnabled', True))).lower()}
    path                = {json.dumps(str(target_group.get('HealthCheckPath') or '/'))}
    protocol            = {json.dumps(str(target_group.get('HealthCheckProtocol') or 'HTTP'))}
    healthy_threshold   = {int(target_group.get('HealthyThresholdCount') or 2)}
    unhealthy_threshold = {int(target_group.get('UnhealthyThresholdCount') or 2)}
    timeout             = {int(target_group.get('HealthCheckTimeoutSeconds') or 5)}
    interval            = {int(target_group.get('HealthCheckIntervalSeconds') or 30)}
  }}
}}
''')
        target_group_refs[source_arn] = f"aws_lb_target_group.{address}.arn"
        coverage.append({"resource": source_arn, "status": "CONTEXT_REPRODUCIBLE", "kind": "TARGET_GROUP"})
    for listener in inventory["listeners"]:
        source_lb = str(listener.get("LoadBalancerArn") or "")
        lb_ref = load_balancer_refs.get(source_lb)
        if not lb_ref:
            continue
        protocol = str(listener.get("Protocol") or "HTTP")
        if protocol not in {"HTTP", "TCP"}:
            blockers.append(f"LISTENER_CERTIFICATE_ADAPTER_REQUIRED:{protocol}")
            continue
        forward = next(
            (
                action
                for action in listener.get("DefaultActions", [])
                if action.get("Type") == "forward"
            ),
            None,
        )
        source_tg = str((forward or {}).get("TargetGroupArn") or "")
        tg_ref = target_group_refs.get(source_tg)
        if not tg_ref:
            blockers.append(f"LISTENER_ACTION_MAPPING_REQUIRED:{listener.get('ListenerArn')}")
            continue
        address = network_tf_address("listener", str(listener.get("ListenerArn") or protocol))
        blocks.append(f'''
resource "aws_lb_listener" "{address}" {{
  load_balancer_arn = {lb_ref}
  port              = {int(listener.get('Port') or 80)}
  protocol          = {json.dumps(protocol)}

  default_action {{
    type             = "forward"
    target_group_arn = {tg_ref}
  }}
}}
''')

    for service in selected_services:
        source_arn = str(service.get("serviceArn") or "")
        service_name = str(service.get("serviceName") or source_arn.rsplit("/", 1)[-1])
        address = network_tf_address("service", service_name)
        cluster_ref = cluster_refs.get(str(service.get("clusterArn") or "")) or primary_cluster_ref
        task_ref = task_definition_refs.get(str(service.get("taskDefinition") or ""))
        if not cluster_ref or not task_ref:
            blockers.append(f"ECS_SERVICE_BINDING_REQUIRED:{service_name}")
            continue
        lines = [
            f'resource "aws_ecs_service" "{address}" {{',
            f'  name            = substr("${{local.prefix}}-{address}", 0, 255)',
            f"  cluster         = {cluster_ref}",
            f"  task_definition = {task_ref}",
            "  desired_count   = 1",
            f"  launch_type     = {json.dumps(str(service.get('launchType') or 'EC2'))}",
        ]
        network = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
        subnet_values = [network_subnet_refs.get(str(value)) for value in network.get("subnets", [])]
        subnet_values = [value for value in subnet_values if value]
        group_values = [network_sg_refs.get(str(value)) for value in network.get("securityGroups", [])]
        group_values = [value for value in group_values if value]
        if subnet_values and group_values:
            lines.extend(
                [
                    "  network_configuration {",
                    f"    subnets          = [{', '.join(subnet_values)}]",
                    f"    security_groups  = [{', '.join(group_values)}]",
                    "    assign_public_ip = false",
                    "  }",
                ]
            )
        for binding in service.get("loadBalancers", []):
            tg_ref = target_group_refs.get(str(binding.get("targetGroupArn") or ""))
            if tg_ref:
                lines.extend(
                    [
                        "  load_balancer {",
                        f"    target_group_arn = {tg_ref}",
                        f"    container_name   = {json.dumps(str(binding.get('containerName') or ''))}",
                        f"    container_port   = {int(binding.get('containerPort') or 80)}",
                        "  }",
                    ]
                )
        lines.append("}")
        blocks.append("\n".join(lines) + "\n")
        coverage.append({"resource": source_arn, "status": "SEMANTIC_MIRROR", "kind": "ECS_SERVICE"})

    external_cidrs = [
        str(node.properties.get("cidr"))
        for node in nodes.values()
        if node.primary_kind == "RNR_ExternalSource" and node.properties.get("cidr")
    ]
    if load_balancer_refs and external_cidrs:
        lb_ref = next(iter(load_balancer_refs.values()))
        blocks.append(f'''
resource "aws_wafv2_ip_set" "authorized_client" {{
  name               = substr("${{local.prefix}}-authorized-client", 0, 128)
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = {json.dumps(external_cidrs)}
}}

resource "aws_wafv2_web_acl" "mirror" {{
  name  = substr("${{local.prefix}}-web-acl", 0, 128)
  scope = "REGIONAL"

  default_action {{ block {{}} }}

  rule {{
    name     = "AllowAuthorizedClient"
    priority = 1
    action {{ allow {{}} }}
    statement {{
      ip_set_reference_statement {{
        arn = aws_wafv2_ip_set.authorized_client.arn
      }}
    }}
    visibility_config {{
      cloudwatch_metrics_enabled = true
      metric_name                = "AllowAuthorizedClient"
      sampled_requests_enabled   = true
    }}
  }}

  visibility_config {{
    cloudwatch_metrics_enabled = true
    metric_name                = "MirrorWebACL"
    sampled_requests_enabled   = true
  }}
}}

resource "aws_wafv2_web_acl_association" "mirror" {{
  resource_arn = {lb_ref}
  web_acl_arn  = aws_wafv2_web_acl.mirror.arn
}}
''')
        coverage.append({"resource": "RNR_WAFWebACL", "status": "SEMANTIC_MIRROR", "kind": "WAF"})
    return "\n".join(blocks), coverage, sorted(set(blockers)), primary_cluster_ref

def generic_terraform(
    scenario: Scenario,
    nodes: dict[str, Node],
    edges: list[Edge],
    context_evidence: dict[str, Any] | None = None,
    mirror_spec: dict[str, Any] | None = None,
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
    network_model = network_model_from_context(context_evidence)
    if network_hcl:
        blocks.append(network_hcl)
    blockers.extend(network_blockers)
    integrated_hcl, integrated_coverage, integrated_blockers, ecs_cluster_ref = (
        render_integrated_services_from_context(
            scenario=scenario,
            nodes=selected_nodes,
            addresses=addresses,
            selected_edges=selected_edges,
            context_evidence=context_evidence,
            mirror_spec=mirror_spec,
            network_subnet_refs=network_subnet_refs,
            network_sg_refs=network_sg_refs,
        )
    )
    if integrated_hcl:
        blocks.append(integrated_hcl)
    blockers.extend(integrated_blockers)
    integrated_kinds = {
        str(value.get("kind")) for value in integrated_coverage
    }
    inventory_services = list(context_inventory(context_evidence).get("ecs_services", []))

    def add_coverage(node: Node, status: str, reason: str) -> None:
        coverage_nodes.append(
            {"node_id": node.id, "kind": node.primary_kind, "status": status, "reason": reason}
        )

    # First pass: principals and standalone resources.
    for node_id, node in selected_nodes.items():
        address = addresses[node_id]
        slug = re.sub(r"[^a-z0-9-]+", "-", node_name(node).lower()).strip("-")[:28] or "resource"
        kind = node.primary_kind
        if kind == "RNR_Environment":
            add_coverage(node, "EVIDENCE_ONLY", "Integrated-graph environment metadata selects the source account and Region; it is not a deployable resource.")
        elif kind == "RNR_ExternalSource":
            add_coverage(node, "EVIDENCE_ONLY", "The authorized source CIDR is evidence and may be referenced by recreated network controls.")
        elif kind in {"RNR_CodeFinding", "RNR_NetworkFinding"}:
            add_coverage(node, "EVIDENCE_ONLY", "Scanner findings describe the path but are not Terraform resources.")
        elif kind == "RNR_AppEndpoint":
            workload_id = str(
                node.properties.get("workload_arn")
                or node.properties.get("workload_id")
                or ""
            )
            artifact = str(
                node.properties.get("artifact_uri")
                or node.properties.get("image_digest")
                or ""
            )
            service_name = str(node.properties.get("service") or "").lower()
            matched_service = next(
                (
                    value
                    for value in inventory_services
                    if service_name
                    and service_name
                    in str(value.get("serviceName") or "").lower()
                ),
                None,
            )
            if matched_service and "ECS_SERVICE" in integrated_kinds:
                add_coverage(node, "CONTEXT_REPRODUCIBLE", "The read-only collector bound this endpoint to an ECS service and task definition rendered into Terraform.")
            elif workload_id and artifact:
                add_coverage(node, "ADAPTER_INPUT_PRESENT", "Endpoint has an explicit workload binding and immutable artifact reference for a service-specific adapter.")
                blockers.append(f"APP_WORKLOAD_ADAPTER_REQUIRED:{node_name(node)}")
            else:
                add_coverage(node, "ARTIFACT_REQUIRED", "Endpoint path/port alone cannot recreate the ECS/EC2/Lambda workload or application code.")
                blockers.append(f"APP_WORKLOAD_BINDING_REQUIRED:{node_name(node)}")
                required_inputs_list.append(
                    {
                        "name": f"app_workload_binding.{address}",
                        "reason": "Provide workload type and ARN/ID plus an approved immutable artifact URI or image digest.",
                    }
                )
        elif kind == "RNR_LoadBalancer":
            load_balancer_arn = node.arn or ""
            collected = any(
                load_balancer_arn
                and value.get("LoadBalancerArn") == load_balancer_arn
                for item in (context_evidence or {}).get("results", [])
                if item.get("status") == "COLLECTED"
                for value in item.get("response", {}).get("LoadBalancers", [])
            )
            add_coverage(
                node,
                "CONTEXT_COLLECTED" if collected else "CONTEXT_REQUIRED",
                "ALB ARN is usable for read-only listener, target-group and network collection; workload targets still require binding.",
            )
            if "ALB" not in integrated_kinds:
                blockers.append(f"LOAD_BALANCER_RENDERER_REQUIRED:{node_name(node)}")
        elif kind == "RNR_WAFWebACL":
            collected = any(
                item.get("status") == "COLLECTED"
                and item.get("request", {}).get("operation") == "get-web-acl"
                for item in (context_evidence or {}).get("results", [])
            )
            add_coverage(
                node,
                "CONTEXT_COLLECTED" if collected else "CONTEXT_REQUIRED",
                "WAF ARN is usable for read-only rule collection; referenced IP sets and managed rule dependencies must also be portable.",
            )
            if "WAF" not in integrated_kinds:
                blockers.append(f"WAF_RENDERER_REQUIRED:{node_name(node)}")
        elif kind == "RNR_SecurityGroup":
            group_id = str(node.properties.get("group_id") or "")
            if group_id in network_sg_refs:
                terraform_refs[node_id] = network_sg_refs[group_id]
                resource_refs[node_id] = network_sg_refs[group_id]
                add_coverage(node, "CONTEXT_REPRODUCIBLE", "Read-only API context supplied the VPC and normalized rules used by the network renderer.")
            else:
                add_coverage(node, "CONTEXT_REQUIRED", "Graph rules do not include the VPC ID needed to recreate this security group safely.")
                blockers.append(f"SECURITY_GROUP_CONTEXT_REQUIRED:{group_id or node_name(node)}")
        elif kind == "RNR_Subnet":
            subnet_id = str(node.properties.get("subnet_id") or "")
            if subnet_id in network_subnet_refs:
                terraform_refs[node_id] = network_subnet_refs[subnet_id]
                resource_refs[node_id] = network_subnet_refs[subnet_id]
                add_coverage(node, "CONTEXT_REPRODUCIBLE", "Read-only API context supplied the VPC, route table and subnet attributes.")
            else:
                add_coverage(node, "CONTEXT_REQUIRED", "A source subnet ID is present, but its VPC and route dependencies require API context.")
                blockers.append(f"SUBNET_CONTEXT_REQUIRED:{subnet_id or node_name(node)}")
        elif kind == "RNR_NetworkAcl":
            acl_id = str(node.properties.get("acl_id") or "")
            if acl_id in network_model["network_acls"]:
                add_coverage(node, "CONTEXT_REPRODUCIBLE", "Read-only API context supplied VPC and subnet associations for the NACL renderer.")
            else:
                add_coverage(node, "CONTEXT_REQUIRED", "Graph entries lack the VPC and subnet associations required by Terraform.")
                blockers.append(f"NETWORK_ACL_CONTEXT_REQUIRED:{acl_id or node_name(node)}")
        elif kind in {"AWS_Organization", "AWS_Account"}:
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
            role_id = next(
                (
                    edge.end
                    for edge in selected_edges
                    if edge.kind == "AWS_RunsAs"
                    and edge.start == node.id
                    and selected_nodes[edge.end].primary_kind == "AWS_Role"
                ),
                None,
            )
            profile_line = ""
            user_data_line = ""
            if role_id:
                profile_address = network_tf_address("instance_profile", address)
                blocks.append(f'''
resource "aws_iam_instance_profile" "{profile_address}" {{
  name = substr("${{local.prefix}}-{profile_address}", 0, 128)
  role = aws_iam_role.{addresses[role_id]}.name
}}
''')
                profile_line = f"  iam_instance_profile   = aws_iam_instance_profile.{profile_address}.name\n"
            if ecs_cluster_ref:
                user_data_line = f'''  user_data = <<-USERDATA
#!/bin/bash
echo "ECS_CLUSTER=${{{ecs_cluster_ref.replace('.id', '.name')}}}" >> /etc/ecs/ecs.config
USERDATA
'''
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
{profile_line}{user_data_line}

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
        if edge.kind in RNR_PATH_EDGE_KINDS:
            runtime_proven = edge.properties.get("runtime_exploit_proven") is True
            validation_status = str(
                edge.properties.get("validation_status") or "UNSPECIFIED"
            )
            status = (
                "RUNTIME_VERIFIED"
                if runtime_proven
                else "PATH_EVIDENCE_ONLY"
            )
            coverage_edges.append(
                {
                    "edge": edge_identifier(edge),
                    "status": status,
                    "actions": list(edge.properties.get("actions") or []),
                    "validation_status": validation_status,
                }
            )
            if edge.kind == "RNR_CanCompromiseWorkloadRole" and not runtime_proven:
                blockers.append(
                    f"RUNTIME_COMPROMISE_NOT_PROVEN:{node_name(selected_nodes[edge.start])}"
                )
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
        "integrated_services": integrated_coverage,
        "edges": coverage_edges,
        "blockers": blockers,
        "required_inputs": required_inputs_list,
        "warning": "Semantic equivalence is targeted; source IDs, secrets, key material, and business data are not cloned.",
        "validation_steps": list((mirror_spec or {}).get("steps", [])),
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
    mirror_spec: dict[str, Any] | None = None,
) -> dict[str, str]:
    renderers = {
        "lambda_update_invoke_admin": lambda: lambda_terraform(scenario, nodes),
        "sts_assume_admin": lambda: sts_terraform(scenario),
        "iam_create_access_key_s3": lambda: create_key_terraform(scenario),
        "role_chain_s3": lambda: role_chain_terraform(scenario),
        "ec2_passrole_spot_admin": lambda: ec2_terraform(scenario),
        "generic_awshound_path": lambda: generic_terraform(scenario, nodes, edges, context_evidence, mirror_spec),
        "integrated_rnr_path": lambda: generic_terraform(scenario, nodes, edges, context_evidence, mirror_spec),
    }
    renderer = renderers.get(scenario.scenario_type)
    if not renderer:
        raise PipelineError(f"Terraform renderer is not implemented: {scenario.scenario_type}")
    return renderer()

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
