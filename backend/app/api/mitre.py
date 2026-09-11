"""Read-only MITRE ATT&CK catalogue intelligence API."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.mitre_intelligence import (
    coverage_analysis,
    list_techniques,
    mitre_overview,
    technique_detail,
    technique_rules,
)

router = APIRouter(prefix="/mitre", tags=["mitre intelligence"])


def canonical_id(value: str) -> str:
    technique_id = value.upper()
    if len(technique_id) > 9:
        raise HTTPException(404, "MITRE ATT&CK technique bulunamadı.")
    return technique_id


@router.get("")
def overview(db: Session = Depends(get_db)):
    return mitre_overview(db)


@router.get("/coverage")
def coverage(db: Session = Depends(get_db)):
    return coverage_analysis(db)


@router.get("/techniques")
def techniques(
    search: str | None = Query(None, max_length=120),
    tactic: str | None = Query(None, max_length=120),
    kind: Literal["all", "technique", "subtechnique"] = "all",
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=250),
    db: Session = Depends(get_db),
):
    return list_techniques(db, search=search, tactic=tactic, kind=kind, offset=offset, limit=limit)


@router.get("/techniques/{technique_id}")
def detail(technique_id: str, db: Session = Depends(get_db)):
    value = technique_detail(db, canonical_id(technique_id))
    if value is None:
        raise HTTPException(404, "MITRE ATT&CK technique bulunamadı.")
    return value


@router.get("/techniques/{technique_id}/rules")
def rules(
    technique_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    value = technique_rules(db, canonical_id(technique_id), offset=offset, limit=limit)
    if value is None:
        raise HTTPException(404, "MITRE ATT&CK technique bulunamadı.")
    return value
