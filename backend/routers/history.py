from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from serialize import model_to_dict
import models

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
def get_history(limit: int = 30, db: Session = Depends(get_db)):
    ips = db.query(models.IPLookup).order_by(models.IPLookup.fetched_at.desc()).limit(limit).all()
    urls = db.query(models.UrlLookup).order_by(models.UrlLookup.checked_at.desc()).limit(limit).all()
    files = db.query(models.FileLookup).order_by(models.FileLookup.last_seen_at.desc()).limit(limit).all()

    items = []
    for r in ips:
        items.append({"type": "ip", "key": r.ip, "score": r.malicious_score, "at": r.fetched_at, "detail": model_to_dict(r)})
    for r in urls:
        items.append({"type": "url", "key": r.url, "score": r.malicious_score, "at": r.checked_at, "detail": model_to_dict(r)})
    for r in files:
        items.append({"type": "file", "key": r.filename or r.sha256[:12], "score": r.risk_score, "at": r.last_seen_at, "detail": model_to_dict(r)})

    items.sort(key=lambda x: x["at"], reverse=True)
    return items[:limit]
