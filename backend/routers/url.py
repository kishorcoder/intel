from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from rate_limit import limiter
from serialize import model_to_dict
from services.url_intel import lookup_url

router = APIRouter(prefix="/api/url", tags=["url"])


class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    refresh: bool = False


@router.post("/")
@limiter.limit("20/minute")
def check_url(request: Request, body: UrlRequest, db: Session = Depends(get_db)):
    row = lookup_url(db, body.url, force_refresh=body.refresh)
    return model_to_dict(row)
