#!/usr/bin/env python3
"""Convert an AWSHound OpenGraph JSON/ZIP into Terraform source files only.

This command is intentionally generation-only. It does not:

- connect to AWS;
- invoke Terraform;
- deploy resources;
- execute an attack;
- collect detection evidence; or
- destroy resources.

The converter reuses converter_core's schema registry, path detectors, generic
renderer, identifier remapping, synthetic-data rules, context collectors, and
coverage gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

import converter_core as core


VERSION = "1.0.0"


class ConversionError(RuntimeError):
    """Raised when a graph cannot be safely converted."""


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")
    return cleaned or "attack-path"


def prepare_output(output: Path, force: bool) -> None:
    if not output.exists():
        output.mkdir(parents=True)
        return
    if not output.is_dir():
        raise ConversionError(f"output is not a directory: {output}")
    children = list(output.iterdir())
    if not children:
        return
    if not force:
        raise ConversionError(
            f"output directory is not empty: {output} (use --force to replace generated output)"
        )
    resolved = output.resolve()
    if resolved == Path(resolved.anchor):
        raise ConversionError("refusing to replace a filesystem root")
    for child in children:
        if child.is_dir() and (child / "conversion-manifest.json").is_file():
            shutil.rmtree(child)
        elif child.is_file() and child.name == "conversion-summary.json":
            child.unlink()
        else:
            raise ConversionError(
                f"refusing --force because output contains an unknown item: {child}"
            )


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def write_json(path: Path, value: object) -> None:
    write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def selected_scenarios(
    document: dict[str, object], wanted: list[str] | None
) -> tuple[dict[str, core.Node], list[core.Edge], list[core.Scenario]]:
    nodes, edges = core.normalize_graph(document)
    scenarios = core.detect_scenarios(nodes, edges)
    if wanted:
        requested = set(wanted)
        scenarios = [item for item in scenarios if item.scenario_id in requested]
        missing = requested - {item.scenario_id for item in scenarios}
        if missing:
            raise ConversionError(
                "requested scenario was not detected: " + ", ".join(sorted(missing))
            )
    if not scenarios:
        raise ConversionError("no supported or generic attack path was detected")
    return nodes, edges, scenarios


def conversion_required_inputs(scenario: core.Scenario) -> dict[str, object]:
    inputs: list[dict[str, object]] = [
        {
            "name": "resource_name_prefix",
            "reason": "New target-account resource names are not source graph IDs.",
        },
        {
            "name": "synthetic_flag",
            "reason": "Source secrets and business data are not copied into Terraform.",
            "sensitive": True,
        },
    ]
    if scenario.scenario_type == "ec2_passrole_spot_admin":
        inputs.append(
            {
                "name": "mirror_ami_id",
                "reason": "This path creates a new EC2 instance and the graph has no source instance AMI.",
            }
        )
    if scenario.scenario_type in {"generic_awshound_path", "integrated_rnr_path"}:
        inputs.extend(
            [
                {
                    "name": "ec2_ami_overrides",
                    "reason": "Provide destination-account AMIs for EC2 nodes when source AMIs are not portable.",
                    "required_when": "The path includes AWS_EC2Instance.",
                },
                {
                    "name": "lambda_package_files",
                    "reason": "Provide approved Lambda ZIPs when synthetic code is insufficient.",
                    "required_when": "The existing application code is an exploit prerequisite.",
                },
                {
                    "name": "allow_partial_reconstruction",
                    "reason": "Explicit acknowledgement is required when terraform-coverage.json has blockers.",
                    "default": False,
                },
            ]
        )
    return {
        "status": "USER_INPUT_REQUIRED",
        "inputs": inputs,
        "prohibited": [
            "Source AWS access keys",
            "Production secrets",
            "Customer data",
            "KMS key material",
        ],
    }


def convert(
    input_path: Path,
    output: Path,
    wanted: list[str] | None,
    force: bool,
    source_profile: str | None = None,
) -> dict[str, object]:
    document, raw = core.load_graph(input_path)
    nodes, edges, scenarios = selected_scenarios(document, wanted)
    prepare_output(output, force)
    source_hash = hashlib.sha256(raw).hexdigest()
    generated: list[dict[str, object]] = []
    used_names: set[str] = set()

    for index, scenario in enumerate(scenarios, start=1):
        directory_name = safe_name(scenario.scenario_id)
        if directory_name in used_names:
            directory_name = f"{directory_name}-{index}"
        used_names.add(directory_name)
        destination = output / directory_name
        destination.mkdir(parents=True, exist_ok=False)

        requests = core.context_plan(scenario, nodes, edges)
        context_evidence = (
            core.collect_context(
                requests,
                source_profile,
                scenario.source_account_id,
            )
            if source_profile
            else None
        )
        files = core.terraform_files(
            scenario,
            nodes,
            edges,
            context_evidence,
        )
        written: list[str] = []
        for relative_name, content in files.items():
            # Terraform and directly required fixture/coverage files only.
            if not (
                relative_name.endswith(".tf")
                or relative_name.startswith("fixtures/")
                or relative_name == "terraform-coverage.json"
            ):
                continue
            write_text(destination / relative_name, content)
            written.append(relative_name)

        write_text(
            destination / "terraform.tfvars.example",
            core.tfvars_example(scenario),
        )
        write_json(
            destination / "context-plan.json",
            {
                "mode": "READ_ONLY",
                "source_profile_required_to_execute": True,
                "requests": [core.asdict(request) for request in requests],
            },
        )
        if context_evidence is not None:
            write_json(destination / "context-evidence.json", context_evidence)
        write_json(
            destination / "required-inputs.json",
            conversion_required_inputs(scenario),
        )
        manifest = {
            "tool": "graph2terraform",
            "tool_version": VERSION,
            "generator_version": core.VERSION,
            "source_file": input_path.name,
            "source_sha256": source_hash,
            "scenario": {
                "scenario_id": scenario.scenario_id,
                "scenario_type": scenario.scenario_type,
                "layers": scenario.layers,
                "mirror_mode": scenario.mirror_mode,
                "source_account_id": scenario.source_account_id,
                "region": scenario.region,
            },
            "safety": {
                "aws_connected": bool(source_profile),
                "source_profile": source_profile,
                "terraform_executed": False,
                "resources_deployed": False,
                "attack_executed": False,
                "source_secrets_copied": False,
            },
            "files": sorted([*written, "context-plan.json"]),
        }
        write_json(destination / "conversion-manifest.json", manifest)
        generated.append(
            {
                "scenario_id": scenario.scenario_id,
                "scenario_type": scenario.scenario_type,
                "directory": str(destination),
                "layers": scenario.layers,
            }
        )

    summary = {
        "tool": "graph2terraform",
        "tool_version": VERSION,
        "input": str(input_path),
        "source_sha256": source_hash,
        "generated_count": len(generated),
        "generated": generated,
        "notice": "Generation only. AWS and Terraform were not executed.",
        "source_context_collected": bool(source_profile),
    }
    write_json(output / "conversion-summary.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert AWSHound OpenGraph JSON/ZIP files to Terraform source only."
    )
    parser.add_argument("--version", action="version", version=f"graph2terraform {VERSION}")
    parser.add_argument("--input", required=True, type=Path, help="AWSHound graph.json or ZIP")
    parser.add_argument("--output", required=True, type=Path, help="generated Terraform directory")
    parser.add_argument(
        "--scenario",
        action="append",
        help="scenario ID to generate; repeatable; default is all detected paths",
    )
    parser.add_argument(
        "--source-profile",
        help=(
            "optional AWS CLI profile used only for allow-listed read-only context APIs; "
            "when omitted, conversion uses graph properties only"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace only directories previously generated by graph2terraform",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = convert(
            args.input,
            args.output,
            args.scenario,
            args.force,
            args.source_profile,
        )
    except (
        ConversionError,
        core.PipelineError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        print(f"graph2terraform: error: {exc}", file=sys.stderr)
        return 2
    print(f"Generated Terraform for {result['generated_count']} path(s):")
    for item in result["generated"]:
        print(
            f"  - {item['scenario_id']} ({item['scenario_type']}): "
            f"{item['directory']}"
        )
    if args.source_profile:
        print(
            f"Read-only AWS context was collected with profile {args.source_profile}. "
            "Terraform was not executed."
        )
    else:
        print("AWS was not contacted and Terraform was not executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
