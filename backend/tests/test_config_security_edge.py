"""Edge-case tests for the config / auth / security layer.

Covers the corners the happy-path smoke + security suites don't dwell on:

  * Config persistence:
      - empty config file ({}) still seeds all three providers
      - missing config file is recreated on first load
      - corrupt config JSON surfaces a clear error (graceful failure)
      - PUT /api/settings with an unknown provider id → 400 (not 500)
      - telemetry_enabled toggle round-trips through disk
      - telemetry_endpoint is empty by default
  * Auth:
      - missing Authorization header → 401
      - wrong bearer token → 401
      - correct bearer token → 200
      - GET /api/auth-token from localhost → 200, returns the token
      - GET /health → 200 with NO auth (preflight)
      - GET /health/docker → 200 with NO auth (preflight)
  * Scan path validation (Q5):
      - /etc, /proc, and ~/.svetovid are all rejected (403)
      - /tmp/<folder> is allowed
      - a nonexistent path → 400
      - a ../ traversal that resolves to a blocked path is rejected (403)
  * Provider defaults + key resolution:
      - GLM model is "glm-5.2"
      - KIMI base_url points at moonshot.cn
      - OLLAMA ships with the non-empty default key "ollama"
      - GLM_API_KEY env var wins over file / keyring

These run against a throwaway HOME with the fail keyring backend so nothing
ever touches the real ~/.svetovid or the macOS Keychain. They do not modify
any existing test file; they sit alongside the rest of the suite.
"""

from __future__ import annotations

import json
import sys

import pytest


# ---------------------------------------------------------------------------
# Hermetic environment: throwaway HOME + fail keyring + fresh svetovid modules.
#
# We force keyring to its no-op fail backend so tests never block on the macOS
# Keychain GUI permission dialog (which would otherwise hang the whole pytest
# session). We also wipe cached ``svetovid.*`` modules between tests so each one
# re-imports fresh module-level state (config paths are computed at import time
# from ``Path.home()``).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    """Run every test against a throwaway ``~/.svetovid``."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.fail.Keyring")
    monkeypatch.setenv("SVETOVID_HITL_AUTO_APPROVE", "1")
    # Clear cached svetovid singletons so each test re-imports fresh state
    # (APP_DIR / CONFIG_FILE are computed at import time from Path.home()).
    for mod in list(sys.modules):
        if mod.startswith("svetovid"):
            del sys.modules[mod]
    yield fake_home


# ===========================================================================
# Config persistence edge cases
# ===========================================================================


def test_empty_config_file_still_seeds_three_providers(isolated_home):
    """An on-disk ``{}`` config must still hydrate all three default providers.

    The loader iterates ``PROVIDER_DEFAULTS`` (not the stored ``providers``
    dict), so even an empty config yields a fully-seeded Settings object rather
    than one with zero providers.
    """
    from pathlib import Path

    from svetovid.config import load_settings

    app_dir = Path(isolated_home) / ".svetovid"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "config.json").write_text("{}")

    s = load_settings()
    assert set(s.providers) == {"ollama", "glm", "kimi"}
    # Each provider carries its label (proves it came from PROVIDER_DEFAULTS,
    # not from the empty stored dict).
    assert s.providers["glm"].label == "GLM (Zhipu BigModel)"
    assert s.active_provider is None


def test_missing_config_file_is_recreated_on_load(isolated_home):
    """First load with no config file creates one and returns defaults."""
    from pathlib import Path

    from svetovid.config import load_settings

    cfg = Path(isolated_home) / ".svetovid" / "config.json"
    assert not cfg.exists()

    s = load_settings()
    assert set(s.providers) == {"ollama", "glm", "kimi"}
    # The config file is now persisted to disk.
    assert cfg.exists()
    on_disk = json.loads(cfg.read_text())
    assert set(on_disk["providers"]) == {"ollama", "glm", "kimi"}


def test_corrupt_config_json_raises_clearly(isolated_home):
    """Corrupt config JSON must surface as a JSON/parse error, not crash opaquely.

    The loader does not silently rewrite a corrupt file; it raises so the caller
    (or the operator) sees the problem. We assert it raises a json error rather
    than returning half-initialized state.
    """
    from pathlib import Path

    from svetovid.config import load_settings

    app_dir = Path(isolated_home) / ".svetovid"
    app_dir.mkdir(parents=True, exist_ok=True)
    (app_dir / "config.json").write_text("{ this is :: not valid json !!!")

    # A corrupt file must NOT silently produce a default-seeded Settings; it
    # should raise so the corruption isn't masked. (If the app ever gains a
    # "recover by reseeding" path, this test should be updated to match it.)
    with pytest.raises(json.JSONDecodeError):
        load_settings()


def test_put_settings_unknown_provider_returns_400(isolated_home):
    """PUT /api/settings with an unknown provider id must return 400.

    The handler validates each provider id against the ProviderId literal and
    rejects unknown ids with a clear 400 — never a 500. (``Literal`` raises
    ``TypeError`` on bad input, not ``ValueError``; the handler must catch both.)
    """
    from fastapi.testclient import TestClient

    from svetovid.main import app, AUTH_TOKEN

    auth = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    with TestClient(app) as client:
        r = client.put(
            "/api/settings",
            json={"providers": {"definitely-not-a-provider": {"model": "x"}}},
            headers=auth,
        )
        assert r.status_code == 400, f"expected 400, got {r.status_code}: {r.text}"
        assert "unknown provider" in r.text.lower(), r.text


def test_telemetry_enabled_toggle_persists(isolated_home):
    """Flipping telemetry_enabled to False round-trips through disk."""
    from svetovid.config import load_settings, save_settings

    s = load_settings()
    assert s.telemetry_enabled is True  # default
    s.telemetry_enabled = False
    save_settings(s)

    s2 = load_settings()
    assert s2.telemetry_enabled is False

    # And it's actually written to the JSON (not just held in memory).
    from pathlib import Path

    cfg = json.loads((Path(isolated_home) / ".svetovid" / "config.json").read_text())
    assert cfg["telemetry_enabled"] is False


def test_telemetry_endpoint_empty_by_default(isolated_home):
    """telemetry_endpoint defaults to '' (opt-out: empty = no upload)."""
    from pathlib import Path

    from svetovid.config import load_settings

    s = load_settings()
    assert s.telemetry_endpoint == ""

    # Also reflected in the on-disk config after a save.
    from svetovid.config import save_settings

    save_settings(s)
    cfg = json.loads((Path(isolated_home) / ".svetovid" / "config.json").read_text())
    assert cfg["telemetry_endpoint"] == ""


def test_reset_wipes_config_and_keys(isolated_home):
    """reset_settings() removes config.json + keys.json; reload reseeds."""
    from pathlib import Path

    from svetovid.config import load_settings, reset_settings, save_settings

    app_dir = Path(isolated_home) / ".svetovid"
    s = load_settings()
    s.providers["glm"].api_key = "some-secret"
    s.telemetry_enabled = False
    save_settings(s)
    cfg = app_dir / "config.json"
    keys = app_dir / "keys.json"
    assert cfg.exists()
    assert keys.exists()

    reset_settings()
    assert not cfg.exists()
    assert not keys.exists()

    # Reload after reset recreates a fresh, fully-seeded config.
    s2 = load_settings()
    assert set(s2.providers) == {"ollama", "glm", "kimi"}
    assert s2.telemetry_enabled is True  # back to default
    assert s2.active_provider is None


# ===========================================================================
# Provider defaults + key resolution
# ===========================================================================


def test_glm_model_is_glm_5_2(isolated_home):
    """GLM's default model is exactly 'glm-5.2'."""
    from svetovid.config import load_settings

    s = load_settings()
    assert s.providers["glm"].model == "glm-5.2"


def test_kimi_base_url_is_moonshot_cn(isolated_home):
    """KIMI's base_url points at Moonshot's API host."""
    from svetovid.config import load_settings

    s = load_settings()
    assert s.providers["kimi"].base_url == "https://api.moonshot.cn/v1"


def test_ollama_has_nonempty_default_key(isolated_home):
    """Ollama ships with the non-empty default api_key 'ollama'.

    OpenAI-compatible clients require a non-empty key; Ollama ignores the value,
    so we seed 'ollama' rather than leave it blank.
    """
    from svetovid.config import load_settings

    s = load_settings()
    assert s.providers["ollama"].api_key == "ollama"
    assert s.providers["ollama"].api_key != ""


def test_glm_api_key_env_var_overrides_file(isolated_home, monkeypatch):
    """GLM_API_KEY env var wins over file-fallback / keyring on load."""
    from svetovid.config import load_settings, save_settings

    # Seed a stored key first.
    s = load_settings()
    s.providers["glm"].api_key = "file-stored-secret"
    save_settings(s)

    # Now set the env var and reload: env must take priority.
    monkeypatch.setenv("GLM_API_KEY", "env-secret-wins")
    s2 = load_settings()
    assert s2.providers["glm"].api_key == "env-secret-wins"


# ===========================================================================
# Auth edge cases
# ===========================================================================


def _client_with_settings():
    """Build a TestClient that has booted the app lifespan (lifespan sets up DB,
    telemetry, etc., and is what /health relies on)."""
    from fastapi.testclient import TestClient

    from svetovid.main import app

    return TestClient(app)


def test_request_without_authorization_header_is_401(isolated_home):
    """A protected endpoint with no Authorization header → 401."""
    with _client_with_settings() as client:
        r = client.get("/api/settings")
        assert r.status_code == 401, r.text
        assert "missing authorization" in r.text.lower(), r.text


def test_request_with_wrong_token_is_401(isolated_home):
    """A protected endpoint with a wrong bearer token → 401."""
    with _client_with_settings() as client:
        r = client.get(
            "/api/settings",
            headers={"Authorization": "Bearer definitely-not-the-right-token"},
        )
        assert r.status_code == 401, r.text
        assert "invalid auth token" in r.text.lower(), r.text


def test_request_with_correct_token_is_200(isolated_home):
    """A protected endpoint with the correct bearer token → 200."""
    from svetovid.main import AUTH_TOKEN

    with _client_with_settings() as client:
        r = client.get(
            "/api/settings",
            headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert "providers" in body


def test_auth_token_from_localhost_returns_token(isolated_home):
    """GET /api/auth-token from a localhost client → 200 with the token.

    TestClient defaults to a 'testclient' host, which the localhost-only guard
    rejects with 403. Passing client=('127.0.0.1', ...) makes the request appear
    to come from loopback, exercising the happy path.
    """
    from fastapi.testclient import TestClient

    from svetovid.main import app, AUTH_TOKEN

    with TestClient(app, client=("127.0.0.1", 60000)) as client:
        r = client.get("/api/auth-token")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["token"] == AUTH_TOKEN


def test_health_requires_no_auth(isolated_home):
    """GET /health → 200 even with no Authorization header (preflight)."""
    with _client_with_settings() as client:
        r = client.get("/health")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert "version" in body


def test_health_docker_requires_no_auth(isolated_home):
    """GET /health/docker → 200 even with no Authorization header (preflight).

    The Docker health check is used by the Tauri shell / preflight and must be
    reachable without a token. (It may legitimately report docker is absent on
    the test machine; we only assert the endpoint is reachable + shaped right.)
    """
    with _client_with_settings() as client:
        r = client.get("/health/docker")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "installed" in body
        assert "running" in body
        assert "images" in body


# ===========================================================================
# Scan path validation (Q5) edge cases
# ===========================================================================


def test_scan_etc_rejected_403(isolated_home):
    """Scanning /etc → 403 (system path)."""
    from svetovid.main import _validate_scan_path
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _validate_scan_path("/etc")
    assert exc.value.status_code == 403
    assert "system path" in exc.value.detail.lower()


def test_scan_proc_rejected_403(isolated_home):
    """Scanning /proc → 403 (system path)."""
    from svetovid.main import _validate_scan_path
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _validate_scan_path("/proc")
    assert exc.value.status_code == 403
    assert "system path" in exc.value.detail.lower()


def test_scan_svetovid_home_rejected_403(isolated_home):
    """Scanning ~/.svetovid → 403 (holds API keys / settings)."""
    from pathlib import Path

    from svetovid.main import _validate_scan_path
    from fastapi import HTTPException

    sv_dir = Path(isolated_home) / ".svetovid"
    sv_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(HTTPException) as exc:
        _validate_scan_path(str(sv_dir))
    assert exc.value.status_code == 403
    assert "svetovid" in exc.value.detail.lower()


def test_scan_tmp_subfolder_allowed(isolated_home, tmp_path_factory):
    """Scanning a folder under the OS temp tree → allowed (resolves fine)."""
    from svetovid.main import _validate_scan_path

    # A real, existing temp dir that's not a system path and not ~/.svetovid.
    evidence = tmp_path_factory.mktemp("evidence")
    result = _validate_scan_path(str(evidence))
    assert str(result) == str(evidence.resolve())


def test_scan_nonexistent_path_rejected_400(isolated_home):
    """Scanning a path that doesn't exist → 400 (not 500)."""
    from svetovid.main import _validate_scan_path
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _validate_scan_path("/tmp/somefolder_that_definitely_does_not_exist_xyz")
    assert exc.value.status_code == 400
    assert "does not exist" in exc.value.detail.lower()


def test_scan_path_traversal_to_blocked_path_rejected_403(isolated_home):
    """A '../' traversal that resolves to a blocked system path is rejected.

    The validator resolves the path (collapsing symlinks + '..') BEFORE
    checking the blocklist, so ``/tmp/../etc`` can't sneak past the /etc guard.
    """
    from svetovid.main import _validate_scan_path
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _validate_scan_path("/tmp/../etc")
    assert exc.value.status_code == 403
    # The detail references the (resolved) blocked system path.
    assert "system path" in exc.value.detail.lower()


def test_scan_endpoint_with_path_traversal_blocked(isolated_home):
    """End-to-end: POST /api/scan with a traversal payload → 403, not 200."""
    from svetovid.main import AUTH_TOKEN

    with _client_with_settings() as client:
        r = client.post(
            "/api/scan",
            json={"path": "/tmp/../etc"},
            headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
        )
        assert r.status_code == 403, r.text
        assert "system path" in r.text.lower()
