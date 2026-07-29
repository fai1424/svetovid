"""Persisted user configuration: LLM providers, sandbox mode, governance toggles.

Stored under ``~/.svetovid/`` (created on first run). API keys are kept in the
OS keyring via ``keyring`` when available, with a fallback to a chmod-600 JSON
file for headless / dev use. Nothing here is committed.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

APP_DIR = Path.home() / ".svetovid"
CONFIG_FILE = APP_DIR / "config.json"
CASES_DIR = APP_DIR / "cases"
AUDIT_DIR = APP_DIR / "audit"

KEYRING_SERVICE = "svetovid"


def ensure_app_dirs() -> None:
    """Create the on-disk app skeleton if missing. Safe to call repeatedly."""
    for d in (APP_DIR, CASES_DIR, AUDIT_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

ProviderId = Literal["ollama", "glm", "kimi"]


class Provider(BaseModel):
    """One OpenAI-compatible LLM endpoint."""

    id: ProviderId
    label: str
    base_url: str
    api_key: str = ""           # stored in keyring at rest; populated on load
    model: str = ""
    # Sensible defaults per provider; user can override.
    temperature: float = 0.2
    max_tokens: int | None = None

    def is_configured(self) -> bool:
        return bool(self.base_url and self.model)


PROVIDER_DEFAULTS: dict[ProviderId, dict] = {
    "ollama": {
        "label": "Ollama (local)",
        "base_url": "http://localhost:11434/v1",
        "model": "llama3.1:8b",
        # Ollama needs a non-empty key; any string works.
        "api_key": "ollama",
    },
    "glm": {
        "label": "GLM (Zhipu BigModel)",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-5.2",
    },
    "kimi": {
        "label": "KIMI (Moonshot)",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "moonshot-v1-8k",
    },
}


SandboxMode = Literal["docker", "host_subprocess", "disabled"]
HITLLevel = Literal["required", "advisory", "off"]


class Settings(BaseModel):
    """Top-level persisted settings."""

    providers: dict[ProviderId, Provider] = Field(default_factory=dict)
    active_provider: ProviderId | None = None  # user picks on ApiKeySetup screen

    sandbox_mode: SandboxMode = "docker"
    docker_image_prefix: str = "svetovid"

    # Governance (A3 / A5): how strict the human-in-the-loop policy is.
    hitl_evidence_collection: HITLLevel = "required"
    hitl_report_release: HITLLevel = "required"
    hitl_tool_execution: HITLLevel = "advisory"

    # Knowledge bases baked into the Docker image.
    attack_version: str = "15.1"          # MITRE ATT&CK Enterprise
    sigma_rules_path: str = "/opt/sigma"

    # Telemetry: anonymous usage analytics (case duration, tool success, etc.)
    telemetry_enabled: bool = True
    telemetry_endpoint: str = ""          # empty = no upload; set to your server URL

    created_at: str = Field(default_factory=lambda: _now_iso())
    updated_at: str = Field(default_factory=lambda: _now_iso())

    def active(self) -> Provider | None:
        if self.active_provider is None:
            return None
        return self.providers.get(self.active_provider)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _keyring_enabled() -> bool:
    """Keyring is only used when not obviously headless and the import works."""
    if sys.platform.startswith("linux") and "DISPLAY" not in os.environ and "WAYLAND_DISPLAY" not in os.environ:
        # headless linux → libsecret often unavailable; fall back to file
        return False
    try:
        import keyring  # noqa: F401
        return True
    except Exception:
        return False


def _store_key(provider_id: ProviderId, api_key: str) -> None:
    if not api_key:
        return
    if _keyring_enabled():
        try:
            import keyring
            keyring.set_password(KEYRING_SERVICE, provider_id, api_key)
            return
        except Exception:
            pass  # fall through to file
    # fallback: chmod-600 sibling file
    keyfile = APP_DIR / "keys.json"
    data = json.loads(keyfile.read_text()) if keyfile.exists() else {}
    data[provider_id] = api_key
    keyfile.write_text(json.dumps(data, indent=2))
    keyfile.chmod(0o600)


def _load_key(provider_id: ProviderId) -> str:
    # 1. Environment variable takes priority (e.g. GLM_API_KEY, KIMI_API_KEY, OLLAMA_API_KEY)
    env_key = os.environ.get(f"{provider_id.upper()}_API_KEY", "")
    if env_key:
        return env_key
    # 2. OS keyring
    if _keyring_enabled():
        try:
            import keyring
            v = keyring.get_password(KEYRING_SERVICE, provider_id)
            if v:
                return v
        except Exception:
            pass
    # 3. File fallback
    keyfile = APP_DIR / "keys.json"
    if keyfile.exists():
        try:
            return json.loads(keyfile.read_text()).get(provider_id, "")
        except Exception:
            return ""
    return ""


def load_settings() -> Settings:
    """Load settings from disk, seeding provider defaults on first run."""
    ensure_app_dirs()

    if not CONFIG_FILE.exists():
        s = Settings()
        for pid, defaults in PROVIDER_DEFAULTS.items():
            s.providers[pid] = Provider(id=pid, **defaults)
        save_settings(s)
        return s

    data = json.loads(CONFIG_FILE.read_text())
    # Re-hydrate providers and re-attach keys from keyring
    providers: dict[ProviderId, Provider] = {}
    for pid, defaults in PROVIDER_DEFAULTS.items():
        stored = data.get("providers", {}).get(pid, {})
        # defaults may include "id" if added in haste — drop it before merging so
        # we don't pass `id` twice when constructing Provider(id=pid, **merged).
        defaults_clean = {k: v for k, v in defaults.items() if k != "id"}
        stored_clean = {k: v for k, v in stored.items() if k != "api_key" and k != "id"}
        merged = {**defaults_clean, **stored_clean}
        p = Provider(id=pid, **merged)
        p.api_key = _load_key(pid) or defaults.get("api_key", "")
        providers[pid] = p

    data["providers"] = providers
    return Settings.model_validate(data)


def save_settings(settings: Settings) -> None:
    """Persist settings; strip api_key into keyring, keep the rest in JSON."""
    ensure_app_dirs()
    for pid, p in settings.providers.items():
        _store_key(pid, p.api_key)

    serializable = settings.model_dump()
    for pid, p in serializable["providers"].items():
        p.pop("api_key", None)
    serializable["updated_at"] = _now_iso()
    CONFIG_FILE.write_text(json.dumps(serializable, indent=2))


def reset_settings() -> None:
    """Wipe persisted config + keys (used by Settings → Reset)."""
    CONFIG_FILE.unlink(missing_ok=True)
    keyfile = APP_DIR / "keys.json"
    if keyfile.exists():
        try:
            data = json.loads(keyfile.read_text())
            for pid in data:
                if _keyring_enabled():
                    try:
                        import keyring
                        keyring.delete_password(KEYRING_SERVICE, pid)
                    except Exception:
                        pass
        except Exception:
            pass
        keyfile.unlink(missing_ok=True)
