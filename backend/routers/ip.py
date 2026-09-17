import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from rate_limit import limiter
from serialize import model_to_dict
from services.ip_intel import lookup_ip

router = APIRouter(prefix="/api/ip", tags=["ip"])


@router.get("/{ip}")
@limiter.limit("20/minute")
def get_ip(request: Request, ip: str, refresh: bool = False, db: Session = Depends(get_db)):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Not a valid IP address")
    row = lookup_ip(db, ip, force_refresh=refresh)
    return model_to_dict(row)
