"""Build the compact local repository from MITRE's official ATT&CK STIX data."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

SOURCE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ROOT = Path(__file__).resolve().parents[3]


def main() -> None:
    raw = urlopen(SOURCE_URL, timeout=120).read()
    bundle = json.loads(raw)
    objects = bundle.get("objects", [])
    parents = {
        item["source_ref"]: item["target_ref"]
        for item in objects
        if item.get("type") == "relationship" and item.get("relationship_type") == "subtechnique-of"
    }
    external_by_stix = {}
    for item in objects:
        for ref in item.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external_by_stix[item.get("id")] = ref["external_id"]
                break
    techniques = []
    for item in objects:
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        tid = external_by_stix.get(item.get("id"))
        if not tid or not tid.startswith("T"):
            continue
        techniques.append({
            "technique_id": tid,
            "name": item.get("name", ""),
            "tactics": sorted({phase.get("phase_name", "").replace("-", " ").title() for phase in item.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"}),
            "description": item.get("description", ""),
            "parent_id": external_by_stix.get(parents.get(item.get("id"))),
            "source": "MITRE_ATTACK_STIX_2_1",
        })
    techniques.sort(key=lambda row: row["technique_id"])
    target = ROOT / "data/mitre/enterprise-techniques.json"
    target.write_text(json.dumps(techniques, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    provenance = {
        "source": "MITRE ATT&CK official STIX 2.1 repository",
        "source_url": SOURCE_URL,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "technique_count": len(techniques),
    }
    (ROOT / "data/mitre/enterprise-techniques-source.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(f"MITRE techniques: {len(techniques)}")


if __name__ == "__main__":
    main()
