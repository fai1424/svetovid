"""Anonymous telemetry + usage analytics for Svetovid.

Privacy contract (enforced everywhere in this package):
  - NO PII. We never collect file paths, evidence content, API keys,
    LLM prompts/responses, user identity, hostnames, or command args.
  - Only aggregate operational metrics: which goal ran, how long it took,
    which tools succeeded/failed, how many iterations, user rating.
  - Identifiers are a single anonymous ``client_id`` UUID stored on disk —
    it names an *installation*, not a person.
  - Telemetry is opt-out (enabled by default) with a clear Settings toggle,
    and nothing is uploaded unless ``settings.telemetry_endpoint`` is set.

Layout:
  client_id.py  — generate + persist the anonymous installation UUID
  collector.py  — EventBus subscriber → per-investigation metrics → SQLite queue
  uploader.py   — periodic batch flush of the SQLite queue to an HTTPS endpoint
  server.py     — reference collection server (FastAPI) for internal deployment
"""
