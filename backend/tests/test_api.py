from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.session import Base, get_db
from app.main import app


engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, expire_on_commit=False)


def override_db():
    with TestingSession() as db:
        yield db


app.dependency_overrides[get_db] = override_db


def test_import_list_detail_and_stats():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    sample = Path(__file__).resolve().parents[2] / "data" / "samples" / "v1-synthetic.rules"
    with TestClient(app) as client, sample.open("rb") as handle:
        imported = client.post("/api/rules/import", files=[("files", (sample.name, handle, "text/plain"))])
        assert imported.status_code == 200, imported.text
        assert imported.json()["imported"] == 20

        listing = client.get("/api/rules", params={"search": "NMAP"})
        assert listing.status_code == 200
        assert listing.json()["total"] == 1
        assert listing.json()["items"][0]["sid"] == 9900001

        detail = client.get("/api/rules/9900001")
        assert detail.status_code == 200
        assert detail.json()["contents"] == []

        stats = client.get("/api/stats")
        assert stats.status_code == 200
        assert stats.json()["total_rules"] == 20
        assert stats.json()["classified_rules"] == 0
        assert stats.json()["manual_review"]["UNREVIEWED"] == 20
        assert stats.json()["manual_review"]["CLASSIFIED_UNREVIEWED"] == 0
        assert stats.json()["manual_review"]["NOT_CLASSIFIED"] == 20


def test_missing_rule_is_404():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as client:
        assert client.get("/api/rules/123456789").status_code == 404
