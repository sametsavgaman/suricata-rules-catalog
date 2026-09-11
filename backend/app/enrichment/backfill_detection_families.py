"""Populate missing deterministic family assignments without changing classifications."""
import argparse
import time

from sqlalchemy.exc import OperationalError

from app.database.session import Base, SessionLocal, engine
from app.services.detection_families import backfill_families


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    Base.metadata.create_all(engine)
    for attempt in range(4):
        with SessionLocal() as db:
            try:
                result = backfill_families(db, limit=args.limit)
                break
            except OperationalError:
                db.rollback()
                if attempt == 3:
                    print("Backfill paused because SQLite remained busy. Re-run the same command to resume.")
                    return 1
        time.sleep(2 ** attempt)
    print(f"Examined: {result['examined']}; assigned: {result['assigned']}; unassigned: {result['unassigned']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
