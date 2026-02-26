import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
import datetime
import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.endpoint import Endpoint
from backend.app.models import Target
from backend.app.schemas.endpoint import EndpointCreate, EndpointOut, EndpointSummary
from backend.app.schemas.endpoint import EndpointOut, EndpointSummary
from backend.app.services.endpoint_service import EndpointService

logger = logging.getLogger(__name__)

router = APIRouter()

_service = EndpointService()


def _to_out(endpoint: Endpoint) -> EndpointOut:
    return EndpointOut(
        id=endpoint.id,
        target_id=endpoint.target_id,
        asset_id=endpoint.asset_id,
        run_id=endpoint.run_id,
        url=endpoint.url,
        scheme=endpoint.scheme,
        host=endpoint.host,
        port=endpoint.port,
        path=endpoint.path,
        method=endpoint.method,
        params=json.loads(endpoint.params_json or "[]"),
        status_code=endpoint.status_code,
        content_type=endpoint.content_type,
        content_length=endpoint.content_length,
        source=endpoint.source,
        is_interesting=endpoint.is_interesting,
        interesting_reason=endpoint.interesting_reason,
        request_headers=json.loads(endpoint.request_headers_json) if endpoint.request_headers_json else None,
        response_headers=json.loads(endpoint.response_headers_json) if endpoint.response_headers_json else None,
        first_seen_at=endpoint.first_seen_at,
        last_seen_at=endpoint.last_seen_at,
        is_new=endpoint.is_new,
        tags=json.loads(endpoint.tags_json or "[]"),
        notes=endpoint.notes,
    )


@router.post("", response_model=EndpointOut, status_code=201)
def create_endpoint(body: EndpointCreate, db: Session = Depends(get_db)):
    if not db.get(Target, body.target_id):
        raise HTTPException(status_code=404, detail="Target not found")
    endpoint = _service.upsert_endpoint(db, body.model_dump())
    _service.link_to_asset(db, endpoint)
    db.commit()
    db.refresh(endpoint)
    logger.info("Upserted endpoint id=%s url=%s", endpoint.id, endpoint.url)
    return _to_out(endpoint)


@router.post("/bulk", status_code=200)
def bulk_upsert_endpoints(body: list[EndpointCreate], db: Session = Depends(get_db)):
    items = [item.model_dump() for item in body]
    result = _service.upsert_bulk(db, items)
    for endpoint in db.query(Endpoint).filter(Endpoint.asset_id.is_(None)).all():
        _service.link_to_asset(db, endpoint)
    db.commit()
    return result


@router.get("", response_model=list[EndpointSummary])
def list_endpoints(
    target_id: int | None = None,
_MAX_LIMIT = 1000


class _EndpointUpdate(BaseModel):
    tags: list[str] | None = None
    notes: str | None = None
    is_interesting: bool | None = None
    interesting_reason: str | None = None


def _to_out(ep: Endpoint) -> EndpointOut:
    return EndpointOut(
        id=ep.id,
        target_id=ep.target_id,
        asset_id=ep.asset_id,
        run_id=ep.run_id,
        url=ep.url,
        scheme=ep.scheme,
        host=ep.host,
        port=ep.port,
        path=ep.path,
        method=ep.method,
        params=json.loads(ep.params_json or "[]"),
        status_code=ep.status_code,
        content_type=ep.content_type,
        content_length=ep.content_length,
        source=ep.source,
        is_interesting=ep.is_interesting,
        interesting_reason=ep.interesting_reason,
        request_headers=json.loads(ep.request_headers_json) if ep.request_headers_json else None,
        response_headers=json.loads(ep.response_headers_json) if ep.response_headers_json else None,
        first_seen_at=ep.first_seen_at,
        last_seen_at=ep.last_seen_at,
        is_new=ep.is_new,
        tags=json.loads(ep.tags_json or "[]"),
        notes=ep.notes,
    )


@router.get("/interesting", response_model=list[EndpointSummary])
def list_interesting(target_id: int, db: Session = Depends(get_db)):
    endpoints = (
        db.query(Endpoint)
        .filter(Endpoint.target_id == target_id, Endpoint.is_interesting.is_(True))
        .order_by(Endpoint.last_seen_at.desc())
        .all()
    )
    return endpoints


@router.get("/params")
def list_params(target_id: int, db: Session = Depends(get_db)):
    endpoints = db.query(Endpoint.params_json).filter(Endpoint.target_id == target_id).all()

    counts: dict[str, int] = {}
    types_map: dict[str, set] = {}

    for (params_json,) in endpoints:
        try:
            params = json.loads(params_json or "[]")
        except (json.JSONDecodeError, TypeError):
            params = []
        for param in params:
            name = param.get("name")
            ptype = param.get("type")
            if not name:
                continue
            counts[name] = counts.get(name, 0) + 1
            types_map.setdefault(name, set()).add(ptype)

    result = [
        {"name": name, "count": count, "types": sorted(t for t in types_map[name] if t)}
        for name, count in counts.items()
    ]
    result.sort(key=lambda x: x["count"], reverse=True)
    return result


@router.get("/stats")
def get_stats(target_id: int, db: Session = Depends(get_db)):
    endpoints = db.query(Endpoint).filter(Endpoint.target_id == target_id).all()

    by_source: dict[str, int] = {}
    by_method: dict[str, int] = {}
    interesting = 0
    new_count = 0
    unique_param_names: set[str] = set()

    for ep in endpoints:
        by_source[ep.source] = by_source.get(ep.source, 0) + 1
        by_method[ep.method] = by_method.get(ep.method, 0) + 1
        if ep.is_interesting:
            interesting += 1
        if ep.is_new:
            new_count += 1
        try:
            params = json.loads(ep.params_json or "[]")
        except (json.JSONDecodeError, TypeError):
            params = []
        for param in params:
            name = param.get("name")
            if name:
                unique_param_names.add(name)

    return {
        "total": len(endpoints),
        "by_source": by_source,
        "by_method": by_method,
        "interesting": interesting,
        "new": new_count,
        "unique_params": len(unique_param_names),
    }


@router.get("", response_model=list[EndpointSummary])
def list_endpoints(
    target_id: int,
    asset_id: int | None = None,
    source: str | None = None,
    method: str | None = None,
    is_interesting: bool | None = None,
    status_code_min: int | None = None,
    status_code_max: int | None = None,
    path_contains: str | None = None,
    param_name_contains: str | None = None,
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
):
    limit: int = 100,
    db: Session = Depends(get_db),
):
    if limit > _MAX_LIMIT:
        raise HTTPException(status_code=400, detail=f"limit must not exceed {_MAX_LIMIT}")

    filters = {
        "target_id": target_id,
        "asset_id": asset_id,
        "source": source,
        "method": method,
        "is_interesting": is_interesting,
        "status_code_min": status_code_min,
        "status_code_max": status_code_max,
        "path_contains": path_contains,
        "param_name_contains": param_name_contains,
    }
    results = _service.search_endpoints(db, filters, skip=skip, limit=limit)
    return results
    endpoints = _service.search_endpoints(db, filters)
    return endpoints[skip : skip + limit]


@router.get("/{endpoint_id}", response_model=EndpointOut)
def get_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    endpoint = db.get(Endpoint, endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return _to_out(endpoint)
    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return _to_out(ep)


@router.patch("/{endpoint_id}", response_model=EndpointOut)
def update_endpoint(endpoint_id: int, body: _EndpointUpdate, db: Session = Depends(get_db)):
    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    update_data = body.model_dump(exclude_none=True)

    if "tags" in update_data:
        ep.tags_json = json.dumps(update_data.pop("tags"))

    for field, value in update_data.items():
        setattr(ep, field, value)

    ep.last_seen_at = datetime.datetime.utcnow()

    db.commit()
    db.refresh(ep)
    logger.info("Updated endpoint id=%s", ep.id)
    return _to_out(ep)
