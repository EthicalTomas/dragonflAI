from __future__ import annotations

import httpx

from app.core.config import settings

_BASE = settings.backend_url.rstrip("/")


def _get(path: str) -> list | dict:
    resp = httpx.get(f"{_BASE}{path}", timeout=10)
    resp.raise_for_status()
    return resp.json()


def _post(path: str, payload: dict) -> dict:
    resp = httpx.post(f"{_BASE}{path}", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


def list_programs() -> list[dict]:
    return _get("/programs")


def create_program(name: str, platform: str, scope_raw: str) -> dict:
    return _post("/programs", {"name": name, "platform": platform, "scope_raw": scope_raw})


def list_targets(program_id: int | None = None) -> list[dict]:
    path = "/targets" if program_id is None else f"/targets?program_id={program_id}"
    return _get(path)


def create_target(program_id: int, value: str, kind: str) -> dict:
    return _post("/targets", {"program_id": program_id, "value": value, "kind": kind})


def list_runs(program_id: int | None = None) -> list[dict]:
    path = "/runs" if program_id is None else f"/runs?program_id={program_id}"
    return _get(path)


def create_run(program_id: int) -> dict:
    return _post("/runs", {"program_id": program_id})
