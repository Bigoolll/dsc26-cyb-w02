
from pathlib import Path
import yaml

path = Path("models/rawaj_scoring.yaml")
model = yaml.safe_load(path.read_text(encoding="utf-8"))

# Change only the protocol for f08.
for flow in model["flows"]:
    if flow["id"] == "f08":
        flow["protocol"] = "tls"

new_threats = [
    ("T27", "analyst_console", "S", "Stolen analyst credentials impersonate a trusted case reviewer", 3, 4),
    ("T28", "analyst_console", "T", "Malicious browser extension alters case decisions before submission", 3, 4),
    ("T29", "analyst_console", "R", "Missing signed decision records let an analyst deny a disputed case action", 2, 4),
    ("T30", "analyst_console", "I", "Shared workstation exposes customer case details to the next user", 3, 4),
    ("T31", "analyst_console", "D", "Repeated case lookups freeze the analyst console during a scam surge", 2, 4),
    ("T32", "analyst_console", "E", "Compromised analyst session gains access to privileged workstation tools", 2, 5),
    ("T33", "case_db", "T", "Unauthorized database writes change case status and investigation outcomes", 2, 5),
    ("T34", "f08", "T", "Case decision values are altered while crossing from office to core", 2, 4),
    ("T35", "f08", "I", "Customer PII is exposed while case decisions move across the network", 2, 5),
    ("T36", "f08", "D", "Database connection exhaustion prevents analysts from recording decisions", 3, 4),
    ("T37", "scorer", "E", "Compromised scoring process abuses its service identity to access core resources", 2, 5),
    ("T38", "feature_store", "I", "Unauthorized feature-store access exposes personal transaction attributes", 3, 5),
]

existing_ids = {item["id"] for item in model["threats"]}
for tid, target, category, title, likelihood, impact in new_threats:
    if tid not in existing_ids:
        model["threats"].append({
            "id": tid,
            "target": target,
            "category": category,
            "title": title,
            "likelihood": likelihood,
            "impact": impact,
            "status": "open",
        })

path.write_text(
    yaml.safe_dump(model, sort_keys=False, allow_unicode=True, width=100),
    encoding="utf-8",
)
print("Model updated.")
print({key: len(model.get(key, [])) for key in ("zones", "elements", "flows", "threats")})
