import re

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from database import get_db
from rate_limit import limiter
from serialize import model_to_dict
from services.file_intel import analyze_file, lookup_hash

router = APIRouter(prefix="/api/files", tags=["files"])

_HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")

MAX_UPLOAD_BYTES = 50 * 1024 * 1024


@router.post("/upload")
@limiter.limit("10/minute")
async def upload_file(request: Request, db: Session = Depends(get_db), file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (50MB limit)")
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    row = analyze_file(db, data, file.filename)
    return model_to_dict(row)


@router.get("/hash/{sha256}")
def get_by_hash(sha256: str, db: Session = Depends(get_db)):
    if not _HASH_RE.match(sha256):
        raise HTTPException(status_code=400, detail="Expected a 64-character SHA256 hex hash")
    row = lookup_hash(db, sha256)
    if row is None:
        return {"found": False, "sha256": sha256.lower(),
                "note": "No local record for this hash — we only recognize hashes of files "
                        "previously uploaded to this tool, since no keyless internet-wide "
                        "malware-hash reputation database is available. Upload the file itself "
                        "for a real analysis."}
    return {"found": True, **model_to_dict(row)}
