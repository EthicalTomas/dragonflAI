import os

import httpx

BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")

_TIMEOUT = 30.0


def get(path: str, params: dict | None = None) -> dict | list:
    with httpx.Client(timeout=_TIMEOUT) as client:
        response = client.get(BACKEND_URL + path, params=params)
        response.raise_for_status()
        return response.json()


def post(path: str, json_body: dict) -> dict:
    with httpx.Client(timeout=_TIMEOUT) as client:
        response = client.post(BACKEND_URL + path, json=json_body)
        response.raise_for_status()
        return response.json()
