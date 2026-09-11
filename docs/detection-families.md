# Detection Families — architecture and operating contract

Detection Families is a read model above immutable Suricata rules and their
versioned classifications. It helps an NDR team browse a capability such as
AnyDesk, Cobalt Strike or DNS Tunneling without rewriting the original rule or
claiming a new ground-truth label.

## Data model

- `detection_families` is the normalized family dictionary. `slug` and `name`
  are unique; `family_type` is TOOL, MALWARE, PRODUCT, BEHAVIOR or VULNERABILITY.
- `rule_family_assignments` stores at most one primary family per rule, the
  source classification ID when applicable, deterministic evidence, provenance
  and the family algorithm version.
- `rule_family_evaluations` is the resume checkpoint. It records both ASSIGNED
  and UNASSIGNED outcomes, so a full 52k backfill is idempotent and an
  evidence-free rule is not repeatedly scanned.

The projection does not edit `rules`, `classifications`, review history,
benchmarks or product decisions. A future multi-family design can add a role or
rank to the assignment table without changing rule history.

## Conservative decision order

`family-v1` emits one primary family or abstains:

1. A classified entity is accepted only when the deterministic entity-candidate
   layer contains the same normalized entity and marks its evidence non-weak.
2. Explicit, bounded aliases in the rule message identify known tools or
   malware such as AnyDesk, Cobalt Strike, Sliver, Nmap and Remcos.
3. Behavioral families require explicit phrases/field combinations. For
   example, DNS Tunneling requires an explicit tunneling phrase; SMB Lateral
   Movement requires SMB plus lateral-movement/remote-service evidence.
4. Remote Access Software uses the exact controlled subcategory or canonical
   T1219 assignment.
5. A CVE family requires an explicit CVE in the rule and an exploitation/web
   attack classification.
6. Otherwise the outcome is UNASSIGNED. Similar wording alone is never enough.

Aliases are normalized before lookup (`Any Desk`, `ANYDESK` and `AnyDesk`
become `AnyDesk` / `anydesk`). New aliases belong in the centralized vocabulary,
not in UI query-specific conditions.

## Provenance

Assignments retain one of: `EXPLICIT_ENTITY`, `EXPLICIT_RULE_NAME`,
`KNOWN_TOOL`, `KNOWN_MALWARE`, `CVE_FAMILY`, `BEHAVIOR_PATTERN` or `MANUAL`.
The evidence JSON identifies the field and matched value/pattern. `UNASSIGNED`
is stored as an evaluation state with a reason, not as a fake family.

## Backfill and ongoing classifications

From the project root:

```powershell
$env:PYTHONPATH="backend"
backend\.venv\Scripts\python.exe -m app.enrichment.backfill_detection_families
```

The worker reads at most 250 rule IDs at a time, releases the read snapshot,
writes one short transaction and commits the checkpoint. Re-running selects only
unevaluated rules or rules whose latest successful classification is newer than
their checkpoint. Existing assignments are retained. A previously UNASSIGNED
rule is reconsidered only when a newer classification becomes available. New
successful classifications run the same projection in a separate
best-effort transaction; family projection failure cannot invalidate a saved
classification.

## Read API

- `GET /api/families?search=AnyDesk&limit=24`
- `GET /api/families?mitre_technique_id=T1219&protocol=tcp`
- `GET /api/families/stats`
- `GET /api/families/{slug}?offset=0&limit=50`
- `GET /api/rules?family=anydesk`

Aggregation, filtering and pagination happen in SQL. Family list pages are
bounded to 50; detail rule pages are bounded to 100. The frontend never loads
all rules to calculate family counts.

## Current limitations

- V1 stores one conservative primary family per rule. A rule with multiple
  meaningful capabilities is not represented as multi-family yet.
- The alias/pattern vocabulary is deliberately bounded and requires code review
  to grow. This keeps the initial catalogue explainable but leaves most rules
  UNASSIGNED.
- Family membership is a navigation aid, not accuracy ground truth or product
  approval. Analysts still inspect raw rules and record product decisions
  separately.
