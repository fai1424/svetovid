"""Svetovid — agentic DFIR desktop app backend.

FastAPI service exposing:
  - REST endpoints for config, evidence scanning, goal registry, case management
  - a single WebSocket (``/ws``) streaming agent events (thought / action /
    observation / tool progress / HITL requests / provenance) to the UI

Layered as (see docs/ARCHITECTURE.md):
  llm/        single OpenAI-compatible client → Ollama / GLM / KIMI
  evidence/   folder scanner with forensic artifact detection
  agent/      LangGraph ReAct harness + streaming event protocol
  goals/      the 22 investigation goals (one file each, plugin registry)
  tools/      MCP-style wrappers over DFIR tooling (Chainsaw, Vol3, TSK, ...)
  sandbox/    Docker-per-call runner, evidence mounted :ro
  governance/ provenance / chain-of-custody / HITL / policy-as-code
  report/     Markdown + CASE-UCO + ATT&CK Navigator renderers
"""

__version__ = "0.1.0"
