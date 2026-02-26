import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.models.endpoint import Endpoint
from backend.app.models import Target
from backend.app.schemas.endpoint import EndpointCreate, EndpointOut, EndpointSummary
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


@router.get("/{endpoint_id}", response_model=EndpointOut)
def get_endpoint(endpoint_id: int, db: Session = Depends(get_db)):
    endpoint = db.get(Endpoint, endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return _to_out(endpoint)
