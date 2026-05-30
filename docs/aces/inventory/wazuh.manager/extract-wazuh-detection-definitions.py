#!/usr/bin/env python3
"""Extract canonical Wazuh rule and decoder definitions from a filesystem root."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


RULE_DIRS = (
    "var/ossec/etc/rules",
    "var/ossec/ruleset/rules",
)
DECODER_DIRS = (
    "var/ossec/etc/decoders",
    "var/ossec/ruleset/decoders",
)
COMPLIANCE_TAGS = (
    "cis",
    "gdpr",
    "gpg13",
    "hipaa",
    "nist_800_53",
    "pci_dss",
    "tsc",
)


@dataclass
class ParsedDefinition:
    definition_id: str
    engine: str
    definition_kind: str
    native_id: str
    name: str
    content_set_ref: str
    source_file_ref: str
    source_start_line: int
    source_end_line: int
    digest_algorithm: str
    canonical_digest: str
    enabled: bool = True
    loaded: bool = True
    parser_accepted: bool = True
    level: int | None = None
    severity: str = ""
    description: str = ""
    match_strings: list[str] = field(default_factory=list)
    regex_patterns: list[str] = field(default_factory=list)
    field_predicates: list[dict[str, str]] = field(default_factory=list)
    decoded_as: list[str] = field(default_factory=list)
    decoder_names: list[str] = field(default_factory=list)
    decoder_fields: list[str] = field(default_factory=list)
    raw_if_sid: list[str] = field(default_factory=list)
    raw_if_matched_sid: list[str] = field(default_factory=list)
    raw_parent_decoders: list[str] = field(default_factory=list)
    if_sid_refs: list[str] = field(default_factory=list)
    if_matched_sid_refs: list[str] = field(default_factory=list)
    parent_definition_refs: list[str] = field(default_factory=list)
    frequency: int | None = None
    timeframe_seconds: int | None = None
    same_source_constraints: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    mitre_attack_ids: list[str] = field(default_factory=list)
    compliance_tags: list[str] = field(default_factory=list)
    tactic_labels: list[str] = field(default_factory=list)
    technique_labels: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def _text(element: ET.Element, tag: str) -> list[str]:
    values: list[str] = []
    for child in element.findall(tag):
        if child.text and child.text.strip():
            values.append(child.text.strip())
    return values


def _split_refs(values: list[str]) -> list[str]:
    refs: list[str] = []
    for value in values:
        refs.extend(part for part in re.split(r"[\s,]+", value.strip()) if part)
    return refs


def _split_csv(values: list[str]) -> list[str]:
    items: list[str] = []
    for value in values:
        items.extend(part.strip() for part in value.split(",") if part.strip())
    return items


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-").lower()
    return slug or "unnamed"


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _canonical_digest(raw_xml: str) -> str:
    try:
        canonical = ET.canonicalize(raw_xml)
    except Exception:
        try:
            canonical = ET.tostring(ET.fromstring(raw_xml), encoding="unicode")
        except Exception:
            canonical = "\n".join(line.rstrip() for line in raw_xml.strip().splitlines())
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _definition_blocks(text: str, tag: str) -> list[tuple[str, int, int]]:
    pattern = re.compile(rf"<{tag}\b[^>]*>.*?</{tag}>", re.DOTALL)
    return [
        (match.group(0), match.start(), match.end())
        for match in pattern.finditer(text)
    ]


def _source_ref(path: Path, root: Path) -> str:
    return "/" + path.relative_to(root).as_posix()


def _parse_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _raw_attrs(raw_xml: str, tag: str) -> dict[str, str]:
    match = re.search(rf"<{tag}\b(?P<attrs>[^>]*)>", raw_xml)
    if not match:
        return {}
    return {
        key: value
        for key, value in re.findall(r'([A-Za-z0-9_.:-]+)="([^"]*)"', match.group("attrs"))
    }


def _raw_text(raw_xml: str, tag: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(rf"<{tag}\b[^>]*>(.*?)</{tag}>", raw_xml, re.DOTALL):
        value = re.sub(r"\s+", " ", match.group(1)).strip()
        if value:
            values.append(value)
    return values


def _raw_empty_tags(raw_xml: str, prefix: str) -> list[str]:
    return [
        match.group(1)
        for match in re.finditer(r"<([A-Za-z0-9_.:-]+)\s*/>", raw_xml)
        if match.group(1).startswith(prefix)
    ]


def _raw_field_predicates(raw_xml: str) -> list[dict[str, str]]:
    predicates: list[dict[str, str]] = []
    for match in re.finditer(r'<field\b(?P<attrs>[^>]*)>(?P<value>.*?)</field>', raw_xml, re.DOTALL):
        attrs = {
            key: value
            for key, value in re.findall(r'([A-Za-z0-9_.:-]+)="([^"]*)"', match.group("attrs"))
        }
        name = attrs.get("name", "").strip()
        if name:
            predicates.append(
                {
                    "field": name,
                    "operator": "matches",
                    "value": re.sub(r"\s+", " ", match.group("value")).strip(),
                }
            )
    return predicates


def _parse_rule(raw_xml: str, path: Path, root: Path, start: int, end: int) -> ParsedDefinition:
    fallback = False
    try:
        element = ET.fromstring(raw_xml)
        attrs = element.attrib
        descriptions = _text(element, "description")
        match_strings = _text(element, "match")
        regex_patterns = _text(element, "regex")
        decoded_as = _text(element, "decoded_as")
        if_sid = _split_refs(_text(element, "if_sid"))
        if_matched_sid = _split_refs(_text(element, "if_matched_sid"))
        groups = _split_csv(_text(element, "group"))
        mitre_attack_ids = _text(element, "mitre/id")
        compliance_tags = [
            f"{tag}:{value}"
            for tag in COMPLIANCE_TAGS
            for value in _split_csv(_text(element, tag))
        ]
        same_source_constraints = [child.tag for child in element if child.tag.startswith("same_")]
        field_predicates = []
        for child in element.findall("field"):
            name = child.attrib.get("name", "").strip()
            value = (child.text or "").strip()
            if name:
                field_predicates.append({"field": name, "operator": "matches", "value": value})
    except ET.ParseError:
        fallback = True
        attrs = _raw_attrs(raw_xml, "rule")
        descriptions = _raw_text(raw_xml, "description")
        match_strings = _raw_text(raw_xml, "match")
        regex_patterns = _raw_text(raw_xml, "regex")
        decoded_as = _raw_text(raw_xml, "decoded_as")
        if_sid = _split_refs(_raw_text(raw_xml, "if_sid"))
        if_matched_sid = _split_refs(_raw_text(raw_xml, "if_matched_sid"))
        groups = _split_csv(_raw_text(raw_xml, "group"))
        mitre_attack_ids = _raw_text(raw_xml, "id")
        compliance_tags = [
            f"{tag}:{value}"
            for tag in COMPLIANCE_TAGS
            for value in _split_csv(_raw_text(raw_xml, tag))
        ]
        same_source_constraints = _raw_empty_tags(raw_xml, "same_")
        field_predicates = _raw_field_predicates(raw_xml)
    native_id = attrs.get("id", "")
    level = _parse_int(attrs.get("level"))
    frequency = _parse_int(attrs.get("frequency"))
    timeframe = _parse_int(attrs.get("timeframe"))
    definition_kind = "correlation_rule" if if_matched_sid or frequency or timeframe else "rule"
    tags = ["parser:fallback-raw-fragment"] if fallback else []
    return ParsedDefinition(
        definition_id=f"wazuh-rule-{_slug(native_id)}",
        engine="wazuh",
        definition_kind=definition_kind,
        native_id=native_id,
        name=descriptions[0] if descriptions else f"Wazuh rule {native_id}",
        content_set_ref="wazuh-rule-corpus",
        source_file_ref=_source_ref(path, root),
        source_start_line=start,
        source_end_line=end,
        digest_algorithm="sha256",
        canonical_digest=_canonical_digest(raw_xml),
        level=level,
        severity=f"wazuh-level-{level}" if level is not None else "",
        description=descriptions[0] if descriptions else "",
        match_strings=match_strings,
        regex_patterns=regex_patterns,
        field_predicates=field_predicates,
        decoded_as=decoded_as,
        raw_if_sid=if_sid,
        raw_if_matched_sid=if_matched_sid,
        frequency=frequency,
        timeframe_seconds=timeframe,
        same_source_constraints=same_source_constraints,
        groups=groups,
        mitre_attack_ids=mitre_attack_ids,
        compliance_tags=compliance_tags,
        tags=tags,
    )


def _parse_decoder(raw_xml: str, path: Path, root: Path, start: int, end: int) -> ParsedDefinition:
    fallback = False
    try:
        element = ET.fromstring(raw_xml)
        attrs = element.attrib
        parent_decoders = _text(element, "parent")
        order_values = _split_csv(_text(element, "order"))
        match_strings = _text(element, "prematch")
        regex_patterns = _text(element, "regex")
    except ET.ParseError:
        fallback = True
        attrs = _raw_attrs(raw_xml, "decoder")
        parent_decoders = _raw_text(raw_xml, "parent")
        order_values = _split_csv(_raw_text(raw_xml, "order"))
        match_strings = _raw_text(raw_xml, "prematch")
        regex_patterns = _raw_text(raw_xml, "regex")
    native_id = attrs.get("name", "")
    tags = ["parser:fallback-raw-fragment"] if fallback else []
    return ParsedDefinition(
        definition_id=f"wazuh-decoder-{_slug(native_id)}",
        engine="wazuh",
        definition_kind="decoder",
        native_id=native_id,
        name=native_id or "Wazuh decoder",
        content_set_ref="wazuh-decoder-corpus",
        source_file_ref=_source_ref(path, root),
        source_start_line=start,
        source_end_line=end,
        digest_algorithm="sha256",
        canonical_digest=_canonical_digest(raw_xml),
        description=f"Wazuh decoder {native_id}" if native_id else "Wazuh decoder",
        match_strings=match_strings,
        regex_patterns=regex_patterns,
        decoder_names=[native_id] if native_id else [],
        decoder_fields=order_values,
        raw_parent_decoders=parent_decoders,
        tags=tags,
    )


def _dedupe_definition_ids(definitions: list[ParsedDefinition]) -> None:
    seen: dict[str, int] = {}
    for definition in definitions:
        base = definition.definition_id
        count = seen.get(base, 0)
        seen[base] = count + 1
        if count:
            definition.definition_id = f"{base}-{count + 1}"


def _resolve_refs(definitions: list[ParsedDefinition]) -> dict[str, list[str]]:
    rule_ids = {
        definition.native_id: definition.definition_id
        for definition in definitions
        if definition.definition_kind in {"rule", "correlation_rule"} and definition.native_id
    }
    decoder_ids = {
        definition.native_id: definition.definition_id
        for definition in definitions
        if definition.definition_kind == "decoder" and definition.native_id
    }
    unresolved: dict[str, list[str]] = {}
    for definition in definitions:
        for raw in definition.raw_if_sid:
            ref = rule_ids.get(raw)
            if ref:
                definition.if_sid_refs.append(ref)
            else:
                unresolved.setdefault(definition.definition_id, []).append(f"if_sid:{raw}")
        for raw in definition.raw_if_matched_sid:
            ref = rule_ids.get(raw)
            if ref:
                definition.if_matched_sid_refs.append(ref)
            else:
                unresolved.setdefault(definition.definition_id, []).append(f"if_matched_sid:{raw}")
        for raw in definition.raw_parent_decoders:
            ref = decoder_ids.get(raw)
            if ref:
                definition.parent_definition_refs.append(ref)
            else:
                unresolved.setdefault(definition.definition_id, []).append(f"parent_decoder:{raw}")
    return unresolved


def _definition_to_json(definition: ParsedDefinition) -> dict[str, Any]:
    omitted = {"raw_if_sid", "raw_if_matched_sid", "raw_parent_decoders"}
    data = {
        key: value
        for key, value in definition.__dict__.items()
        if key not in omitted and value not in ("", None, [], {})
    }
    return data


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    if path.suffix == ".gz":
        with path.open("wb") as raw_fh, gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw_fh,
            mtime=0,
        ) as gzip_fh, io.TextIOWrapper(gzip_fh, encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
    else:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _without_definitions(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "definitions"}


def _split_manifest(manifest: dict[str, Any], *, definition_kind: str) -> dict[str, Any]:
    definitions = [
        definition
        for definition in manifest["definitions"]
        if (
            definition["definition_kind"] == definition_kind
            if definition_kind == "decoder"
            else definition["definition_kind"] != "decoder"
        )
    ]
    corpus_lines = [
        f"{record['definition_id']} {record['canonical_digest']}"
        for record in definitions
        if "canonical_digest" in record
    ]
    digest = hashlib.sha256(("\n".join(corpus_lines) + "\n").encode("utf-8")).hexdigest()
    split = _without_definitions(manifest)
    split["definition_count"] = len(definitions)
    split["corpus_digest"] = digest
    split["definition_subset"] = "decoders" if definition_kind == "decoder" else "rules"
    split["definitions"] = definitions
    return split


def extract(root: Path) -> dict[str, Any]:
    definitions: list[ParsedDefinition] = []
    parse_errors: list[dict[str, str]] = []
    for rel_dir, tag, parser in (
        *[(rel, "rule", _parse_rule) for rel in RULE_DIRS],
        *[(rel, "decoder", _parse_decoder) for rel in DECODER_DIRS],
    ):
        directory = root / rel_dir
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*.xml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for raw_xml, start_offset, end_offset in _definition_blocks(text, tag):
                start_line = _line_number(text, start_offset)
                end_line = _line_number(text, end_offset)
                try:
                    definitions.append(parser(raw_xml, path, root, start_line, end_line))
                except Exception as exc:
                    parse_errors.append(
                        {
                            "source_file_ref": _source_ref(path, root),
                            "source_start_line": str(start_line),
                            "error": str(exc),
                        }
                    )
    _dedupe_definition_ids(definitions)
    unresolved = _resolve_refs(definitions)
    records = [_definition_to_json(definition) for definition in definitions]
    corpus_lines = [
        f"{record['definition_id']} {record['canonical_digest']}"
        for record in records
        if "canonical_digest" in record
    ]
    corpus_digest = hashlib.sha256(("\n".join(corpus_lines) + "\n").encode("utf-8")).hexdigest()
    rule_count = sum(record["definition_kind"] in {"rule", "correlation_rule"} for record in records)
    decoder_count = sum(record["definition_kind"] == "decoder" for record in records)
    return {
        "schema_version": 1,
        "asset": "wazuh.manager",
        "engine": "wazuh",
        "manager_id": "techvault-wazuh-manager",
        "source_roots": [f"/{root}" for root in (*RULE_DIRS, *DECODER_DIRS)],
        "definition_count": len(records),
        "rule_definition_count": rule_count,
        "decoder_definition_count": decoder_count,
        "corpus_digest_algorithm": "sha256",
        "corpus_digest": corpus_digest,
        "parse_error_count": len(parse_errors),
        "parse_errors": parse_errors,
        "unresolved_reference_count": sum(len(values) for values in unresolved.values()),
        "unresolved_references": unresolved,
        "definitions": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--rules-output", type=Path)
    parser.add_argument("--decoders-output", type=Path)
    parser.add_argument("--summary-output", type=Path)
    args = parser.parse_args()
    manifest = extract(args.root.resolve())
    if not any((args.output, args.rules_output, args.decoders_output, args.summary_output)):
        parser.error("one of --output, --rules-output, --decoders-output, or --summary-output is required")
    if args.output:
        _write_json(args.output, manifest)
    if args.rules_output:
        _write_json(args.rules_output, _split_manifest(manifest, definition_kind="rule"))
    if args.decoders_output:
        _write_json(args.decoders_output, _split_manifest(manifest, definition_kind="decoder"))
    if args.summary_output:
        _write_json(args.summary_output, _without_definitions(manifest))
    if manifest["parse_error_count"]:
        print(f"parse errors: {manifest['parse_error_count']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
