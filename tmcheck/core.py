"""Validation and analysis of YAML STRIDE threat models."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str
    category: str


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str


SECTIONS = ("zones", "elements", "flows", "threats")
STRIDE = "STRIDE"
KINDS = {"external_entity", "process", "data_store"}
STATUSES = {"open", "mitigated", "accepted"}
ENCRYPTED = {"https", "tls", "mtls", "sftp", "ssh"}


def _items(model: dict, section: str) -> list:
    return model.get(section) or []


def _index(model: dict, section: str) -> dict:
    return {item["id"]: item for item in _items(model, section)}


def _valid_score(value) -> bool:
    return type(value) is int and 1 <= value <= 5


def load_model(path) -> dict:
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            model = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError, TypeError, ValueError) as exc:
        raise ModelError(str(exc)) from exc
    if not isinstance(model, dict):
        raise ModelError("The top-level YAML value must be a mapping")
    for section in SECTIONS:
        if model.get(section) is None:
            model[section] = []
        elif not isinstance(model[section], list):
            raise ModelError(f"{section} must be a list")
    return model


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set(STRIDE)
    if kind == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"Unknown element kind: {kind}")


def validate(model: dict) -> list[Issue]:
    issues: set[Issue] = set()

    def add(ref, code):
        issues.add(Issue(ref, code))

    ids = [item["id"] for section in SECTIONS for item in _items(model, section)]
    for identifier, count in Counter(ids).items():
        if count > 1:
            add(identifier, "DUPLICATE_ID")

    zones = _index(model, "zones")
    elements = _index(model, "elements")
    flows = _index(model, "flows")
    for element in _items(model, "elements"):
        ref = element["id"]
        if element.get("kind") not in KINDS:
            add(ref, "BAD_KIND")
        if element.get("zone") not in zones:
            add(ref, "UNKNOWN_ZONE")

    for flow in _items(model, "flows"):
        ref = flow["id"]
        source = flow.get("source")
        target = flow.get("target")
        if source not in elements or target not in elements:
            add(ref, "UNKNOWN_REF")
        if source == target or (source in elements and target in elements and
                                elements[source].get("kind") != "process" and
                                elements[target].get("kind") != "process"):
            add(ref, "INVALID_FLOW")

    for threat in _items(model, "threats"):
        ref = threat["id"]
        target = threat.get("target")
        category = threat.get("category")
        if target not in elements and target not in flows:
            add(ref, "UNKNOWN_REF")
        if category not in STRIDE or not isinstance(category, str) or len(category) != 1:
            add(ref, "BAD_CATEGORY")
        elif target in elements or target in flows:
            if target in flows:
                allowed = applicable("data_flow")
            else:
                element = elements[target]
                try:
                    allowed = applicable(element.get("kind"), is_log=element.get("is_log", False))
                except ValueError:
                    allowed = None
            if allowed is not None and category not in allowed:
                add(ref, "INAPPLICABLE_CATEGORY")
        if not _valid_score(threat.get("likelihood")) or not _valid_score(threat.get("impact")):
            add(ref, "BAD_SCORE")
        status = threat.get("status")
        if status not in STATUSES:
            add(ref, "BAD_STATUS")
        elif status == "mitigated" and not str(threat.get("mitigation") or "").strip():
            add(ref, "MISSING_MITIGATION")
        elif status == "accepted" and not str(threat.get("justification") or "").strip():
            add(ref, "MISSING_JUSTIFICATION")
    return sorted(issues)


def crossing_flows(model: dict) -> list[str]:
    elements = _index(model, "elements")
    result = []
    for flow in _items(model, "flows"):
        source = elements.get(flow.get("source"))
        target = elements.get(flow.get("target"))
        if source is not None and target is not None and source.get("zone") != target.get("zone"):
            result.append(flow["id"])
    return result


def coverage_gaps(model: dict) -> list[Gap]:
    elements = _index(model, "elements")
    flows = _index(model, "flows")
    scope = set(crossing_flows(model))
    for flow_id in list(scope):
        flow = flows[flow_id]
        scope.update((flow["source"], flow["target"]))
    covered = {(t.get("target"), t.get("category")) for t in _items(model, "threats")}
    gaps = []
    for ref in scope:
        if ref in flows:
            categories = applicable("data_flow")
        elif ref in elements:
            element = elements[ref]
            try:
                categories = applicable(element.get("kind"), is_log=element.get("is_log", False))
            except ValueError:
                continue
        else:
            continue
        for category in categories:
            if (ref, category) not in covered:
                gaps.append(Gap(ref, category))
    return sorted(gaps, key=lambda gap: (gap.ref, STRIDE.index(gap.category)))


def policy_findings(model: dict) -> list[Issue]:
    elements = _index(model, "elements")
    zones = _index(model, "zones")
    flows = _index(model, "flows")
    findings: set[Issue] = set()
    for ref in crossing_flows(model):
        flow = flows[ref]
        if str(flow.get("protocol", "")).lower() not in ENCRYPTED:
            findings.add(Issue(ref, "UNENCRYPTED_CROSSING"))
        source_zone = zones.get(elements[flow["source"]].get("zone"))
        target_zone = zones.get(elements[flow["target"]].get("zone"))
        if (source_zone is not None and target_zone is not None and
            target_zone.get("trust", 0) > source_zone.get("trust", 0) and
            flow.get("authenticated") is not True):
            findings.add(Issue(ref, "UNAUTHENTICATED_INBOUND"))
    disclosed = {t.get("target") for t in _items(model, "threats") if t.get("category") == "I"}
    for element in _items(model, "elements"):
        if (element.get("kind") == "data_store" and element.get("holds_pii") is True and
                element["id"] not in disclosed):
            findings.add(Issue(element["id"], "PII_STORE_WITHOUT_I_THREAT"))
    return sorted(findings)


def _natural_key(value: str):
    return tuple((1, int(part)) if part.isdigit() else (0, part) for part in re.split(r"(\d+)", value))


def rank(model: dict) -> list[RankedThreat]:
    selected = [t for t in _items(model, "threats") if t.get("status") == "open" and
                _valid_score(t.get("likelihood")) and _valid_score(t.get("impact"))]
    selected.sort(key=lambda t: (-t["likelihood"] * t["impact"], -t["impact"], _natural_key(t["id"])))
    result = []
    for threat in selected:
        score = threat["likelihood"] * threat["impact"]
        level = "high" if score >= 15 else "medium" if score >= 8 else "low"
        result.append(RankedThreat(threat["id"], score, level))
    return result
