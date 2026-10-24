
"""Command line interface for tmcheck."""
import json
import sys
from dataclasses import asdict

from .core import (
    ModelError,
    load_model,
    validate,
    coverage_gaps,
    policy_findings,
    rank,
)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2

    try:
        model = load_model(argv[0])
    except ModelError as exc:
        print(f"tmcheck: {exc}", file=sys.stderr)
        return 2

    issues = validate(model)

    if issues:
        gaps = []
        policy = []
    else:
        gaps = coverage_gaps(model)
        policy = policy_findings(model)

    ranked = rank(model)

    result = {
        "issues": [asdict(item) for item in issues],
        "gaps": [asdict(item) for item in gaps],
        "policy": [asdict(item) for item in policy],
        "ranked": [asdict(item) for item in ranked],
    }

    print(json.dumps(result, indent=2))

    return 1 if issues or gaps or policy else 0


if __name__ == "__main__":
    raise SystemExit(main())
