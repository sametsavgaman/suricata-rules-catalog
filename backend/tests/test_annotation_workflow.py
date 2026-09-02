from app.evaluation.review import apply_approve, apply_dispute, ordered_records
from app.evaluation.schemas import AnnotationStatus, AnnotationProposal, GoldenRecord, AgreementStatus
from app.evaluation.verifier import calculate_agreement
from app.knowledge.mitre_repository import MitreRepository
from app.evaluation.verifier import verify_record

def rec():
    return GoldenRecord(sid=1, rev=1, msg='ET SCAN inbound port scan', source_file='x', raw_rule='alert tcp any any -> any 1433 (msg:"ET SCAN inbound port scan"; sid:1; rev:1;)', stratum='SCAN', proposal=AnnotationProposal(detected_behavior='scan',category='Reconnaissance',subcategory='Port Scan',proposal_confidence=.95,notes='x'))

def test_approve_is_explicit_and_copies_proposal():
    r=rec(); assert r.annotation.status==AnnotationStatus.UNREVIEWED; apply_approve(r,'a'); assert r.annotation.status==AnnotationStatus.REVIEWED; assert r.expected.category=='Reconnaissance'; assert r.proposal.proposal_status=='AI_PROPOSED'

def test_dispute_not_reviewed():
    r=rec(); apply_dispute(r,'a','wrong'); assert r.annotation.status==AnnotationStatus.DISPUTED

def test_agreement_threshold():
    r=rec(); v=verify_record(r,MitreRepository()); assert calculate_agreement(.95,v) in AgreementStatus

def test_review_order():
    a=rec(); a.agreement_status=AgreementStatus.DISAGREEMENT; b=rec(); b.sid=2; b.agreement_status=AgreementStatus.HIGH_CONFIDENCE_AGREEMENT; assert ordered_records([a,b])[0].sid==2
