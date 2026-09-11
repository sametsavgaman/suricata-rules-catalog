"""Create implicit NOT_EVALUATED product rows for existing catalog rules."""
from sqlalchemy import select
from app.database.models import Rule, RuleProductDecision, ProductStatus
from app.database.session import SessionLocal, Base, engine, ensure_schema_extensions

def main():
    Base.metadata.create_all(bind=engine); ensure_schema_extensions(); created=0
    with SessionLocal() as db:
        existing={x for (x,) in db.execute(select(RuleProductDecision.rule_id)).all()}
        for rule_id, in db.execute(select(Rule.id)).all():
            if rule_id not in existing:
                db.add(RuleProductDecision(rule_id=rule_id, status=ProductStatus.NOT_EVALUATED)); created += 1
        db.commit()
    print(f"Product decision rows created: {created}")

if __name__ == "__main__": main()
