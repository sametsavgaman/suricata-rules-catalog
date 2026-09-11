import random
import re
from collections import defaultdict
from pathlib import Path

from app.evaluation.schemas import ParserSummary, RuleSample
from app.ingestion.rule_loader import RuleLoader
from app.parser.suricata_parser import SuricataRuleParser


STRATA = (
    "SCAN", "MALWARE", "TROJAN", "EXPLOIT", "POLICY", "INFO", "DNS", "WEB",
    "C2_CNC", "REMOTE_ACCESS", "CREDENTIAL", "SUSPICIOUS_HTTP", "TLS", "SMB",
    "GENERIC_TCP", "GENERIC_UDP", "OTHER",
)


def _stratum(msg: str | None, protocol: str, raw_rule: str) -> str:
    text = f"{msg or ''} {raw_rule}".lower()
    prefix_patterns = (
        ("SCAN", r"\bet\s+scan\b"), ("MALWARE", r"\bet\s+malware\b"),
        ("TROJAN", r"\bet\s+trojan\b"), ("EXPLOIT", r"\bet\s+exploit\b"),
        ("POLICY", r"\bet\s+policy\b"), ("INFO", r"\bet\s+info\b"),
    )
    for name, pattern in prefix_patterns:
        if re.search(pattern, text):
            return name
    if re.search(r"\b(c2|c&c|cnc|command and control)\b", text):
        return "C2_CNC"
    if re.search(r"\b(anydesk|teamviewer|screenconnect|remote access|remote admin|rdp)\b", text):
        return "REMOTE_ACCESS"
    if re.search(r"\b(credential|password|mimikatz|logon|login)\b", text):
        return "CREDENTIAL"
    if re.search(r"\b(smb|dce_rpc|445)\b", text):
        return "SMB"
    if protocol.lower() == "dns" or "dns." in text:
        return "DNS"
    if protocol.lower() == "tls" or "tls." in text:
        return "TLS"
    if re.search(r"\bet\s+web_(?:server|client)\b", text):
        return "WEB"
    if protocol.lower() in {"http", "http2"} or "http." in text:
        return "SUSPICIOUS_HTTP"
    if protocol.lower() == "tcp":
        return "GENERIC_TCP"
    if protocol.lower() == "udp":
        return "GENERIC_UDP"
    return "OTHER"


def scan_rules(rules_dir: Path) -> tuple[list[RuleSample], ParserSummary]:
    loader, parser = RuleLoader(), SuricataRuleParser()
    samples: list[RuleSample] = []
    failures: list[dict] = []
    total = 0
    files = sorted(rules_dir.rglob("*.rules")) if rules_dir.exists() else []
    for path in files:
        try:
            loaded = loader.load_file(path)
        except Exception as exc:
            failures.append({"source_file": str(path), "error": f"loader: {exc}"})
            continue
        for raw_rule in loaded.rules:
            total += 1
            try:
                parsed = parser.parse(raw_rule)
                samples.append(RuleSample(
                    sid=parsed.sid,
                    rev=parsed.rev,
                    msg=parsed.msg,
                    source_file=str(path.relative_to(rules_dir)),
                    raw_rule=raw_rule,
                    stratum=_stratum(parsed.msg, parsed.protocol, raw_rule),
                ))
            except Exception as exc:
                if len(failures) < 100:
                    failures.append({"source_file": str(path.relative_to(rules_dir)), "raw_rule": raw_rule[:500], "error": str(exc)})
    parsed_count = len(samples)
    return samples, ParserSummary(
        data_status="REAL_DATA_AVAILABLE" if files else "REAL_DATA_NOT_AVAILABLE",
        source_directory=str(rules_dir),
        total_rules=total,
        parsed_successfully=parsed_count,
        failed_parsing=max(0, total - parsed_count),
        parser_success_rate=(parsed_count / total if total else 0.0),
        rule_files=len(files),
        failures=failures,
    )


def stratified_sample(records: list[RuleSample], count: int, seed: int) -> list[RuleSample]:
    unique = {(record.sid, record.rev): record for record in records}
    buckets: dict[str, list[RuleSample]] = defaultdict(list)
    for record in unique.values():
        buckets[record.stratum].append(record)
    rng = random.Random(seed)
    for bucket in buckets.values():
        bucket.sort(key=lambda item: (item.sid, item.rev))
        rng.shuffle(bucket)
    selected: list[RuleSample] = []
    while len(selected) < min(count, len(unique)):
        added = False
        for name in STRATA:
            if buckets[name] and len(selected) < count:
                selected.append(buckets[name].pop())
                added = True
        if not added:
            break
    return selected

