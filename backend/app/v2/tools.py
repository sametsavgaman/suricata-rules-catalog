import re
from pathlib import Path
from app.evaluation.golden_dataset import read_jsonl
from app.evaluation.schemas import AnnotationStatus, GoldenRecord
from app.knowledge.mitre_repository import MitreRepository
from app.parser.models import ParsedRule

STRONG_NAMES={
 "anydesk":("AnyDesk","Remote Access Tool"),"teamviewer":("TeamViewer","Remote Access Tool"),"screenconnect":("ScreenConnect","Remote Access Tool"),
 "nmap":("Nmap","Attack Tool"),"powershell":("PowerShell","Software"),"pwdump3e":("Pwdump3e","Attack Tool"),
 "predator":("Predator","Malware"),"lumma stealer":("Lumma Stealer","Malware"),"raspberry robin":("Raspberry Robin","Malware"),
 "mmrat":("MMRAT","Malware"),"realrat":("Realrat","Malware"),"brunhilda":("Brunhilda","Malware"),"reconshark":("ReconShark","Malware"),
 "sloppylemming":("SloppyLemming","Malware"),"weevely":("Weevely","Malware"),"gobrat":("GobRAT","Malware"),"nivesro":("Nivesro","Malware"),
 "cobalt strike":("Cobalt Strike","Attack Tool"),
 "internet explorer":("Internet Explorer","Product"),"msie":("Internet Explorer","Product"),
 "nso group":("NSO Group","Other"),"tor":("Tor","Software"),
 "sjavawebmanage":("SJavaWebManage","Malware"),"clickfix":("ClickFix","Attack Tool"),
 "easebay resources login manager":("Easebay Resources Login Manager","Product"),
 "simplis cms":("Simplis CMS","Product"),"guild wars":("Guild Wars","Software"),
 "bearshare":("BearShare","Software"),"emule":("eMule","Software"),
 "hmap":("Hmap","Attack Tool"),"realwin scada":("RealWin SCADA Server","Product"),
 "dbpoweramp audio player":("dBpowerAMP Audio Player","Product"),
 "leadtools imaging":("LEADTOOLS Imaging","Product"),"mediaget":("MediaGet","Software"),
 "eldorado.bho":("Eldorado.BHO","Malware"),
}

# These ET values describe broad platforms or rule deployment scope, not a
# particular product fingerprint.  They must never become entities by
# themselves.
GENERIC_AFFECTED_PRODUCTS = {
    "any", "linux", "windows", "web_browsers", "web_browser_plugins",
    "web_server_applications", "windows_xp_vista_7_8_10_server_32_64_bit",
}

NAMED_TAGS = {
    "threatview_cs": ("Cobalt Strike", "Attack Tool"),
    "zoho_assist": ("Zoho Assist", "Remote Access Tool"),
    "tor": ("Tor", "Software"),
}


def _append_candidate(out: list[dict], name: str, kind: str, evidence_type: str, source: str) -> None:
    if not any(item["candidate"].casefold() == name.casefold() for item in out):
        out.append({
            "candidate": name,
            "entity_type": kind,
            "evidence_type": evidence_type,
            "source": source,
            "weak": False,
            "deterministic": True,
        })

def entity_candidates(rule: ParsedRule) -> list[dict]:
    text=" ".join([rule.msg or "",*rule.contents,*rule.metadata]).casefold(); out=[]
    for needle,(name,kind) in STRONG_NAMES.items():
        if re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", text):
            _append_candidate(out, name, kind, "EXPLICIT_RULE_NAME", "msg/content/metadata")
    for item in rule.metadata:
        folded = item.casefold()
        if folded.startswith("malware_family "):
            name=item.split(" ",1)[1].replace("_"," ")
            if name.casefold() not in {"unknown","generic"}:
                _append_candidate(out, name, "Malware", "EXPLICIT_MALWARE_NAME", "metadata.malware_family")
        elif folded.startswith("affected_product "):
            raw = item.split(" ", 1)[1]
            if raw.casefold() not in GENERIC_AFFECTED_PRODUCTS:
                _append_candidate(out, raw.replace("_", " "), "Product", "SPECIFIC_AFFECTED_PRODUCT", "metadata.affected_product")
        elif folded.startswith("tag "):
            tag = item.split(" ", 1)[1].casefold()
            if tag in NAMED_TAGS:
                name, kind = NAMED_TAGS[tag]
                _append_candidate(out, name, kind, "NAMED_ET_TAG", "metadata.tag")
    if rule.destination_port in {"1433","3306","21"}: out.append({"candidate":{"1433":"MSSQL","3306":"MySQL","21":"FTP"}[rule.destination_port],"entity_type":"Product","evidence_type":"PORT_ONLY","source":"destination_port","weak":True})
    return out

def extract_cves(rule: ParsedRule) -> list[dict]:
    text=" ".join([rule.msg or "",*rule.metadata,*rule.references]); ids=sorted(set(re.findall(r"CVE[-_](\d{4})[-_](\d{4,7})",text,re.I)))
    return [{"id":f"CVE-{y}-{n}","source":"rule msg/metadata/reference","untrusted":True} for y,n in ids]

KEYWORDS={"brute force":{"T1110"},"credential dump":{"T1003"},"pwdump":{"T1003"},"service scan":{"T1046"},"port scan":{"T1046"},"remote access":{"T1219"},"anydesk":{"T1219"},"teamviewer":{"T1219"},"sql injection":{"T1190"},"file inclusion":{"T1190"},"exploit":{"T1190"},"powershell":{"T1059.001"},"dns c2":{"T1071.004"},"cnc domain":{"T1071.004"},"http c2":{"T1071.001"}}
def search_mitre(rule: ParsedRule, repository: MitreRepository, limit=5) -> list[dict]:
    text=" ".join([rule.msg or "",rule.classtype or "",*rule.metadata]).casefold(); scores={}
    for phrase,ids in KEYWORDS.items():
        if phrase in text:
            for tid in ids: scores[tid]=scores.get(tid,0)+0.55
    for item in rule.metadata:
        m=re.match(r"mitre_technique_id\s+(T\d{4}(?:\.\d{3})?)",item,re.I)
        if m: scores[m.group(1).upper()]=scores.get(m.group(1).upper(),0)+0.9
    out=[]
    for tid,score in sorted(scores.items(),key=lambda x:-x[1])[:limit]:
        t=repository.get(tid)
        if t: out.append({"id":t.technique_id,"name":t.name,"tactics":list(t.tactics),"score":min(score,.99)})
    return out

def source_mitre_mapping(rule: ParsedRule, repository: MitreRepository) -> dict | None:
    """Extract source metadata mapping without inventing missing values."""
    for item in rule.metadata:
        m = re.match(r"mitre_technique_id\s+(T\d{4}(?:\.\d{3})?)", item, re.I)
        if m:
            tid = m.group(1).upper(); technique = repository.get(tid)
            result = {"technique_id": tid, "source": "SURICATA_METADATA"}
            if technique:
                result.update(technique_name=technique.name, tactic=technique.tactics[0] if technique.tactics else None,
                              resolution_source="LOCAL_MITRE_REPOSITORY")
            return result
    return None

def search_similar_rules(rule: ParsedRule, golden_path: Path, limit=3) -> list[dict]:
    tokens=set(re.findall(r"[a-z0-9]{3,}",(rule.msg or "").casefold()))-{"the","and","observed","possible"}; rows=[]
    for r in read_jsonl(golden_path,GoldenRecord):
        if r.sid==rule.sid or r.annotation.status!=AnnotationStatus.REVIEWED: continue
        other=set(re.findall(r"[a-z0-9]{3,}",(r.msg or "").casefold()))-{"the","and","observed","possible"}; score=len(tokens&other)/max(1,len(tokens|other))
        if score>=.2: rows.append({"sid":r.sid,"similarity":round(score,3),"classification":r.expected.model_dump(),"source":"AUDITED_BENCHMARK"})
    return sorted(rows,key=lambda x:-x["similarity"])[:limit]
