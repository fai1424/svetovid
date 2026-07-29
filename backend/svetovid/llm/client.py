"""Single LLM client fronting every supported provider.

All three providers (Ollama / GLM / KIMI) speak the OpenAI Chat Completions
API, so we use one client (``langchain_openai.ChatOpenAI``) and vary only the
``base_url`` and the API key. Tool-calling therefore works uniformly — the
catch is that smaller / open models are less reliable at structured tool use,
so tool schemas in this codebase are kept flat (one level of args, primitive
types only) to maximize compatibility.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from langchain_openai import ChatOpenAI

from ..config import Provider, load_settings


class LLMConnectionError(RuntimeError):
    """Raised when a provider endpoint is unreachable or auth fails."""


def build_chat(provider: Provider, *, streaming: bool = True) -> ChatOpenAI:
    """Construct a LangChain ``ChatOpenAI`` bound to ``provider``.

    ``streaming`` defaults to True because the Investigation screen consumes
    tokens incrementally; pass False for one-shot helper calls (e.g. report
    polish).
    """
    if not provider.is_configured():
        raise LLMConnectionError(
            f"Provider {provider.id!r} is not configured (need base_url + model)."
        )
    if not provider.api_key:
        raise LLMConnectionError(
            f"Provider {provider.id!r} is missing its API key. "
            "Set it on the API Key screen first."
        )

    return ChatOpenAI(
        model=provider.model,
        base_url=provider.base_url,
        api_key=provider.api_key,
        temperature=provider.temperature,
        max_tokens=provider.max_tokens,
        streaming=streaming,
        # GLM / KIMI sometimes advertise tool-calling inconsistently; keep
        # calls defensive (we bind_tools lazily, only when a graph runs).
        timeout=60,
        max_retries=2,
    )


async def test_connection(provider: Provider) -> dict[str, Any]:
    """Hit ``GET {base_url}/models`` and report a structured status.

    Returns ``{"ok": bool, "status": str, "detail": str, "models": [...]}``.
    Used by the ApiKeySetup screen's "Test connection" button. Does NOT
    construct a ChatOpenAI — we want a raw probe so we can distinguish
    network / auth / parse errors precisely.
    """
    base = provider.base_url.rstrip("/")
    if not base:
        return {"ok": False, "status": "misconfigured", "detail": "base_url is empty", "models": []}

    headers = {"Authorization": f"Bearer {provider.api_key}"} if provider.api_key else {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{base}/models", headers=headers)
    except httpx.ConnectError as e:
        return {"ok": False, "status": "unreachable", "detail": str(e), "models": []}
    except httpx.TimeoutException:
        return {"ok": False, "status": "timeout", "detail": "no response in 10s", "models": []}
    except httpx.HTTPError as e:
        return {"ok": False, "status": "error", "detail": str(e), "models": []}

    if resp.status_code == 401 or resp.status_code == 403:
        return {"ok": False, "status": "auth_failed", "detail": f"HTTP {resp.status_code}", "models": []}
    if resp.status_code != 200:
        return {
            "ok": False,
            "status": "http_error",
            "detail": f"HTTP {resp.status_code}: {resp.text[:200]}",
            "models": [],
        }

    try:
        body = resp.json()
    except Exception as e:
        return {"ok": False, "status": "bad_json", "detail": str(e), "models": []}

    # OpenAI shape: {"data": [{"id": "..."}, ...]}; Ollama: {"models": [{"name": ...}]}
    models: list[str] = []
    if isinstance(body, dict):
        for item in body.get("data") or []:
            if isinstance(item, dict) and (mid := item.get("id") or item.get("name")):
                models.append(mid)
        if not models:
            for item in body.get("models") or []:
                if isinstance(item, dict) and (mid := item.get("name") or item.get("id")):
                    models.append(mid)

    selected_ok = provider.model in models if (provider.model and models) else True
    status = "connected" if selected_ok else "connected_model_missing"
    return {
        "ok": True,
        "status": status,
        "detail": f"{len(models)} model(s) available" + (
            "" if selected_ok else f" — configured model {provider.model!r} not in list"
        ),
        "models": models[:100],
    }


async def test_active() -> dict[str, Any]:
    """Convenience: test whatever provider is currently active."""
    settings = load_settings()
    active = settings.active()
    if active is None:
        return {"ok": False, "status": "no_active", "detail": "no active provider", "models": []}
    return await test_connection(active)


def _sync_wrap(coro):
    """Run an async probe from sync code (used by CLI/debug scripts)."""
    return asyncio.get_event_loop().run_until_complete(coro)
