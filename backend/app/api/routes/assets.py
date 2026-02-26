import datetime
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models import Endpoint, Target
from backend.app.models.asset import Asset, AssetType
from backend.app.schemas.asset import AssetOut, AssetSummary, AssetUpdate
from backend.app.schemas.endpoint import EndpointSummary

logger = logging.getLogger(__name__)

router = APIRouter()


def _to_out(asset: Asset) -> AssetOut:
    return AssetOut(
        id=asset.id,
        target_id=asset.target_id,
        run_id=asset.run_id,
        asset_type=asset.asset_type,
        value=asset.value,
        resolved_ips=json.loads(asset.resolved_ips_json or "[]"),
        is_alive=asset.is_alive,
        status_code=asset.status_code,
        title=asset.title,
        tech=json.loads(asset.tech_json or "[]"),
        web_server=asset.web_server,
        content_length=asset.content_length,
        cdn=asset.cdn,
        ports=json.loads(asset.ports_json or "[]"),
        first_seen_at=asset.first_seen_at,
        last_seen_at=asset.last_seen_at,
        is_new=asset.is_new,
        tags=json.loads(asset.tags_json or "[]"),
        notes=asset.notes,
    )


@router.get("/stats")
def get_stats(target_id: int, db: Session = Depends(get_db)):
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found")

    row = (
        db.query(
            func.count(Asset.id).label("total"),
            func.sum(case((Asset.is_alive == True, 1), else_=0)).label("alive"),
            func.sum(case((Asset.is_alive == False, 1), else_=0)).label("dead"),
            func.sum(case((Asset.is_alive.is_(None), 1), else_=0)).label("unprobed"),
            func.sum(case((Asset.is_new == True, 1), else_=0)).label("new"),
            func.sum(case((Asset.asset_type == AssetType.SUBDOMAIN, 1), else_=0)).label("subdomain"),
            func.sum(case((Asset.asset_type == AssetType.IP, 1), else_=0)).label("ip"),
            func.sum(case((Asset.asset_type == AssetType.CIDR, 1), else_=0)).label("cidr"),
        )
        .filter(Asset.target_id == target_id)
        .one()
    )

    return {
        "total": row.total or 0,
        "alive": row.alive or 0,
        "dead": row.dead or 0,
        "unprobed": row.unprobed or 0,
        "new": row.new or 0,
        "by_type": {
            "subdomain": row.subdomain or 0,
            "ip": row.ip or 0,
            "cidr": row.cidr or 0,
        },
    }


@router.get("", response_model=list[AssetSummary])
def list_assets(
    target_id: int,
    asset_type: str | None = None,
    is_alive: bool | None = None,
    is_new: bool | None = None,
    search: str | None = None,
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
):
    if not db.get(Target, target_id):
        raise HTTPException(status_code=404, detail="Target not found")

    query = db.query(Asset).filter(Asset.target_id == target_id)
    if asset_type is not None:
        query = query.filter(Asset.asset_type == asset_type)
    if is_alive is not None:
        query = query.filter(Asset.is_alive == is_alive)
    if is_new is not None:
        query = query.filter(Asset.is_new == is_new)
    if search is not None:
        escaped = search.replace("%", r"\%").replace("_", r"\_")
        query = query.filter(Asset.value.ilike(f"%{escaped}%", escape="\\"))

    return query.order_by(Asset.last_seen_at.desc()).offset(skip).limit(limit).all()


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _to_out(asset)


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, body: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = body.model_dump(exclude_unset=True)
    if "tech" in update_data:
        update_data["tech_json"] = json.dumps(update_data.pop("tech"))
    if "ports" in update_data:
        update_data["ports_json"] = json.dumps(update_data.pop("ports"))
    if "tags" in update_data:
        update_data["tags_json"] = json.dumps(update_data.pop("tags"))

    update_data["last_seen_at"] = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    for field, value in update_data.items():
        setattr(asset, field, value)

    db.commit()
    db.refresh(asset)
    logger.info("Updated asset id=%s", asset.id)
    return _to_out(asset)


@router.get("/{asset_id}/endpoints", response_model=list[EndpointSummary])
def list_asset_endpoints(
    asset_id: int,
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return (
        db.query(Endpoint)
        .filter(Endpoint.asset_id == asset_id)
        .offset(skip)
        .limit(limit)
        .all()
    )
