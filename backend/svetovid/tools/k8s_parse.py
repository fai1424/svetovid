"""Kubernetes / container artifact parser tool wrapper (research item C17c-sibling).

Parses the common container / Kubernetes forensic artifacts using only the
standard modules already present in the ``svetovid/base`` image (python3 +
``json`` / stdlib). One tool, ``k8s_parse``, takes an ``artifact_type``
selector and an ``evidence_subpath`` and returns structured rows. Supported:

  - audit_log      : Kubernetes API audit log (JSON lines) → verb / user /
                     objectRef / responseStatus — the API-call timeline.
  - pod_logs       : /var/log/pods/ directory tree → per-pod container log
                     output, namespaces, timestamps.
  - kubelet_logs   : kubelet journal/syslog lines → container lifecycle,
                     image pulls, mount failures.
  - etcd_state     : etcd snapshot (exported keyspace JSON / KV dump) →
                     cluster config: pods, secrets refs, RBAC, deployments
                     (read-only parse — never writes to etcd).
  - image_history  : container image manifest history (``docker inspect`` /
                     ``crane config`` JSON, or a saved manifest.json) → layer
                     commands, created-by, entrypoint — supply-chain tampering.
  - runtime_events : CRI / Falco / Tetragon / Sysdig detection events
                     (JSON lines) → rule, severity, container, process.
  - network_policy : Calico / Cilium NetworkPolicy + namespace manifests
                     (YAML/JSON) → policy names, ingress/egress, namespaces —
                     lateral-movement surface.

For every parsed artifact we return rows tailored to that type. All evidence
access is read-only (etcd snapshots are exported JSON, never a live backup).

CLI shape (inside the container)::

    python3 -c '<PARSER>' <artifact_type> <target>

The parser emits one JSON object per row to stdout; the wrapper collects them,
persists a provenance copy at ``/work/k8s_<type>.jsonl`` and parses them into
structured data. ``host_fallback=True`` lets the parser run on the host
(no Docker) so the unit tests exercise it without a sandbox.

Follows the same event-publishing pattern as chainsaw / aleapp_parse /
linux_logs: tool.start, tool.stdout/stderr, tool.end, agent.action,
agent.observation, provenance.recorded.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..agent import events as E
from .base import Tool, ToolContext, ToolResult


# ---------------------------------------------------------------------------
# artifact_type → human description (used by the agent to pick the right type)
# ---------------------------------------------------------------------------

ARTIFACT_TYPES: dict[str, str] = {
    "audit_log": (
        "Kubernetes API server audit log (JSON lines) — verb, user, "
        "objectRef (resource/namespace/name), responseStatus, sourceIPs. "
        "This is the primary API-call timeline for pod/namespace activity."
    ),
    "pod_logs": (
        "/var/log/pods/ directory tree — per-pod container stdout/stderr "
        "output, namespace + pod name + container, with line timestamps."
    ),
    "kubelet_logs": (
        "kubelet journal/syslog lines — container lifecycle (create/start/"
        "stop/kill), image pulls, mount failures, PLEG events."
    ),
    "etcd_state": (
        "etcd snapshot (exported keyspace JSON or KV dump, read-only) — "
        "cluster config: pods, deployments, secrets refs, RBAC rules, "
        "namespaces. Shows cluster-state changes the API audit may miss."
    ),
    "image_history": (
        "container image manifest history (docker inspect / crane config "
        "JSON or a saved manifest.json) — layer commands, created-by, "
        "entrypoint, env. Detects supply-chain tampering / backdoored images."
    ),
    "runtime_events": (
        "CRI / Falco / Tetragon / Sysdig detection events (JSON lines) — "
        "rule, severity, container, process, syscall. Runtime detections of "
        "container escape, privilege escalation, suspicious exec."
    ),
    "network_policy": (
        "Calico / Cilium NetworkPolicy + namespace manifests (YAML/JSON) — "
        "policy names, ingress/egress rules, namespaces. Maps the lateral-"
        "movement / namespace-egress surface."
    ),
}


# ---------------------------------------------------------------------------
# Inline parser — a self-contained python3 program run inside svetovid/base.
# Takes <artifact_type> <target> on argv and emits JSON rows to stdout.
# Keeping the parser in python3 means we don't fight shell quoting and get
# reliable structured rows across every artifact type. All file access is
# read-only; etcd snapshots are parsed from exported JSON, never mounted live.
# ---------------------------------------------------------------------------

_PARSER = r'''
import json, os, re, sys

fmt = sys.argv[1]
target = sys.argv[2]            # /evidence/<subpath> or empty for discovery
out = sys.stdout

def emit(row):
    out.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    out.flush()


# ---- file discovery ------------------------------------------------------

def discover(target, names=(), exts=()):
    """Walk /evidence (or target) for files matching names or extensions."""
    found = []
    roots = [target] if target and os.path.isdir(target) else \
            ([target] if target and os.path.isfile(target) else ["/evidence"])
    lnames = tuple(n.lower() for n in names)
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            for fn in fns:
                fl = fn.lower()
                if lnames and fl in lnames:
                    found.append(os.path.join(dp, fn))
                elif exts and fl.endswith(exts):
                    found.append(os.path.join(dp, fn))
    return found


def read_text(path, limit=8 * 1024 * 1024):
    try:
        with open(path, "rb") as f:
            data = f.read(limit)
        for enc in ("utf-8", "utf-16", "latin-1"):
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        emit({"error": f"read failed for {path}: {e}"})
        return ""


def each_json_line(paths):
    """Yield parsed JSON objects from one or more JSONL/log files. Lines that
    are not valid JSON are emitted as {"raw": line} so nothing is silently
    dropped."""
    for p in paths:
        emitted_any = False
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    try:
                        yield p, json.loads(line)
                        emitted_any = True
                    except json.JSONDecodeError:
                        yield p, {"raw": line}
                        emitted_any = True
        except Exception as e:
            if not emitted_any:
                emit({"source": os.path.basename(p), "error": f"read: {e}"})


# ---- audit_log (k8s API audit JSONL) --------------------------------------

def parse_audit_log(target):
    # Kubernetes audit logs are JSON lines: one event per line, keys include
    # stageTimestamp / requestReceivedTimestamp, verb, user (username/groups),
    # sourceIPs, objectRef (resource/namespace/name), responseStatus
    # (code/reason), and annotations (often authorization decision attributes).
    paths = []
    if target and os.path.isfile(target):
        paths = [target]
    else:
        names = ("audit.log", "kube-apiserver-audit.log", "apiserver-audit.log")
        paths = discover(target, names=names, exts=(".log",))
        # also pick up any .jsonl that looks like audit (heuristic by name)
        extra = discover(target, exts=(".jsonl",))
        for p in extra:
            if "audit" in p.lower():
                paths.append(p)
        # de-dup, preserve order
        seen = set(); ordered = []
        for p in paths:
            if p not in seen:
                seen.add(p); ordered.append(p)
        paths = ordered

    count = 0
    for p, obj in each_json_line(paths):
        if "raw" in obj and len(obj) == 1:
            continue  # unparseable non-audit line; skip the summary
        # only treat as audit if it has at least one tell-tale field
        if not any(k in obj for k in ("verb", "objectRef", "responseStatus", "user")):
            continue
        ref = obj.get("objectRef") or {}
        resp = obj.get("responseStatus") or {}
        user = obj.get("user") or {}
        emit({
            "artifact_type": "audit_log",
            "source": os.path.basename(p),
            "timestamp": obj.get("stageTimestamp") or obj.get("requestReceivedTimestamp"),
            "verb": obj.get("verb", ""),
            "user": user.get("username", ""),
            "user_groups": user.get("groups", []),
            "sourceIPs": obj.get("sourceIPs", []),
            "resource": ref.get("resource", ""),
            "subresource": ref.get("subresource", ""),
            "namespace": ref.get("namespace", ""),
            "name": ref.get("name", ""),
            "apiVersion": ref.get("apiVersion", ""),
            "code": resp.get("code"),
            "reason": resp.get("reason", ""),
            "annotations": obj.get("annotations") or {},
            "userAgent": obj.get("userAgent", ""),
        })
        count += 1
    emit({"artifact_type": "audit_log",
          "summary": f"{count} audit event(s) across {len(paths)} file(s)"})


# ---- pod_logs (/var/log/pods/ tree) ---------------------------------------

def parse_pod_logs(target):
    """Read the /var/log/pods/ tree.

    Layout (per-pod, per-container, per-restart rotated logs):
        /var/log/pods/<namespace>_<pod>_<pod-uid>/<container>/<restart>.log

    Each *.log line is prefixed with an RFC3339 timestamp:
        2024-06-01T12:00:00.123456787Z stderr F <message>

    We surface namespace, pod, container, restart index, and the message.
    """
    roots = []
    if target and os.path.isdir(target):
        roots = [target]
    elif target and os.path.isfile(target):
        roots = [target]
    else:
        for r in ("/evidence/var/log/pods", "/evidence/var/log/containers"):
            if os.path.isdir(r):
                roots.append(r)
        if not roots:
            # discovery: find any /var/log/pods anywhere under /evidence
            for dp, dns, fns in os.walk("/evidence"):
                if os.path.basename(dp) in ("pods", "containers"):
                    roots.append(dp)

    POD_DIR_RE = re.compile(
        r'^(?P<namespace>[^_]+)_(?P<pod>.+)_(?P<uid>[0-9a-f-]{20,})$'
    )
    PODLOG_LINE_RE = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+'
        r'(?P<stream>stdout|stderr)\s+(?P<flags>\S+)\s+(?P<msg>.*)$'
    )

    count = 0
    pod_dirs_seen = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, dns, fns in os.walk(root):
            # ``dp`` is either a pod directory (namespace_pod_uid) or a
            # container subdirectory living directly under a pod directory:
            #   /var/log/pods/<namespace>_<pod>_<uid>/<container>/<restart>.log
            # We resolve the pod dir + container name once per directory.
            base = os.path.basename(dp)
            parent_base = os.path.basename(os.path.dirname(dp)) if dp != root else ""
            pod_dir_name = base
            container = ""
            mdir = POD_DIR_RE.match(base)
            if mdir:
                # dp IS the pod dir → logs may live one level down (uncommon),
                # but handle direct children too.
                container = ""
            else:
                # dp is presumably the container subdir; check its parent.
                mparent = POD_DIR_RE.match(parent_base)
                if mparent:
                    pod_dir_name = parent_base
                    container = base
                    mdir = mparent
            pod_ns = pod = pod_uid = ""
            if mdir:
                pod_ns = mdir.group("namespace")
                pod = mdir.group("pod")
                pod_uid = mdir.group("uid")
                pod_dirs_seen.add(pod_dir_name)
            for fn in fns:
                if not fn.endswith(".log"):
                    continue
                fp = os.path.join(dp, fn)
                # restart index is the filename stem (e.g. "0.log" → "0")
                restart = fn[:-4] if fn.lower().endswith(".log") else fn
                try:
                    with open(fp, encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.rstrip("\n")
                            ml = PODLOG_LINE_RE.match(line)
                            if ml:
                                d = ml.groupdict()
                                emit({
                                    "artifact_type": "pod_logs",
                                    "source": fp,
                                    "namespace": pod_ns,
                                    "pod": pod,
                                    "pod_uid": pod_uid,
                                    "container": container,
                                    "restart": restart,
                                    "timestamp": d["ts"],
                                    "stream": d["stream"],
                                    "message": d["msg"],
                                })
                                count += 1
                            else:
                                emit({
                                    "artifact_type": "pod_logs",
                                    "source": fp,
                                    "namespace": pod_ns,
                                    "pod": pod,
                                    "container": container,
                                    "restart": restart,
                                    "message": line,
                                })
                                count += 1
                except Exception as e:
                    emit({"artifact_type": "pod_logs", "source": fp, "error": f"read: {e}"})
    emit({"artifact_type": "pod_logs",
          "summary": f"{count} pod-log line(s) across {len(pod_dirs_seen)} pod dir(s)"})


# ---- kubelet_logs (journal/syslog) ----------------------------------------

KUBELET_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'
    r'(?P<rest>.*)$'
)
KUBELET_KEYWORDS = (
    "kubelet", "PLEG", "containerd", "docker", "pull", "CreateContainer",
    "StartContainer", "KillContainer", "RemoveContainer", "SyncPod",
    "ImageGarbageCollected", "FailedMount", "CRI",
)


def parse_kubelet_logs(target):
    paths = []
    if target and os.path.isfile(target):
        paths = [target]
    else:
        names = ("kubelet.log", "kubelet", "kubelet.journal")
        paths = discover(target, names=names, exts=(".log",))
        # also pick up journal exports / syslog that mention kubelet
        extra = discover(target, exts=(".journal",))
        paths.extend(extra)
        seen = set(); ordered = []
        for p in paths:
            if p not in seen:
                seen.add(p); ordered.append(p)
        paths = ordered

    count = 0
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    low = line.lower()
                    if not any(kw.lower() in low for kw in KUBELET_KEYWORDS):
                        continue
                    m = KUBELET_RE.match(line)
                    ts = m.group("ts") if m else ""
                    body = m.group("rest") if m else line
                    emit({
                        "artifact_type": "kubelet_logs",
                        "source": os.path.basename(p),
                        "timestamp": ts,
                        "message": body,
                        "raw": line,
                    })
                    count += 1
        except Exception as e:
            emit({"artifact_type": "kubelet_logs", "source": os.path.basename(p),
                  "error": f"read: {e}"})
    emit({"artifact_type": "kubelet_logs",
          "summary": f"{count} kubelet line(s) across {len(paths)} file(s)"})


# ---- etcd_state (exported keyspace JSON / KV dump) ------------------------

ETCD_KEY_RE = re.compile(
    r'/registry/(?P<resource>[^/]+)(?:/(?P<namespace>[^/]+))?/(?P<name>[^/]+)$'
)


def _decode_etcd_field(raw):
    """Decode an etcd key/value field that may be base64 or already plaintext.

    ``etcdctl get / --prefix -w json`` base64-encodes both keys and values.
    Some export tools emit them pre-decoded. We keep the value if it is
    already a readable string; otherwise we try base64 and fall back to the
    original (k8s values are often protobuf, so decoding may yield binary —
    we replace invalid bytes rather than crash).
    """
    if not isinstance(raw, str) or not raw:
        return raw
    # Heuristic: readable /registry paths contain slashes and printable ASCII.
    if "/" in raw and all(0x20 <= ord(c) < 0x7F for c in raw):
        return raw
    import base64
    try:
        decoded = base64.b64decode(raw, validate=True)
        return decoded.decode("utf-8", "replace")
    except Exception:
        return raw


def _iter_etcd_records(target):
    """Yield (key, value_obj) pairs from an etcd export.

    Supports two common export shapes collected by responders:
      1. ``etcdctl get / --prefix -w json`` → {"kvs":[{"key":<b64>, "value":<b64>}]}
      2. a JSONL/ndjson dump of {"key": "...", "value": {...}} rows
    """
    files = []
    if target and os.path.isfile(target):
        files = [target]
    else:
        files = discover(target, names=("etcd.json", "etcd-snapshot.json",
                                         "etcd.jsonl", "etcd-dump.json"),
                         exts=(".json", ".jsonl"))
    for p in files:
        txt = read_text(p)
        if not txt.strip():
            continue
        # shape 1: single JSON object with kvs
        try:
            payload = json.loads(txt)
        except Exception:
            # maybe JSONL
            for line in txt.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if isinstance(row, dict) and "key" in row:
                    yield p, row.get("key", ""), row.get("value")
            continue
        if isinstance(payload, dict) and isinstance(payload.get("kvs"), list):
            for kv in payload["kvs"]:
                if not isinstance(kv, dict):
                    continue
                key = _decode_etcd_field(kv.get("key", ""))
                vv = kv.get("value", "")
                val = _decode_etcd_field(vv) if isinstance(vv, str) and vv else vv
                yield p, key, val
        elif isinstance(payload, dict) and "value" in payload:
            yield p, payload.get("key", ""), payload.get("value")


def parse_etcd_state(target):
    count = 0
    by_kind = {}
    for p, key, val in _iter_etcd_records(target):
        if not key:
            continue
        m = ETCD_KEY_RE.match(key)
        if not m:
            # still record cluster-level keys (configmaps at cluster scope, etc.)
            emit({
                "artifact_type": "etcd_state",
                "source": os.path.basename(p),
                "key": key,
                "resource": "",
                "namespace": "",
                "name": "",
                "value_excerpt": _excerpt(val),
            })
            count += 1
            continue
        resource = m.group("resource")
        namespace = m.group("namespace") or ""
        name = m.group("name") or ""
        by_kind[resource] = by_kind.get(resource, 0) + 1
        # flag high-signal resources
        sensitive = resource in (
            "secrets", "pods", "deployments", "roles", "rolebindings",
            "clusterroles", "clusterrolebindings", "serviceaccounts",
            "daemonsets", "statefulsets", "cronjobs", "configmaps",
        )
        emit({
            "artifact_type": "etcd_state",
            "source": os.path.basename(p),
            "key": key,
            "resource": resource,
            "namespace": namespace,
            "name": name,
            "sensitive": sensitive,
            "value_excerpt": _excerpt(val),
        })
        count += 1
    breakdown = ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items())) or "(none)"
    emit({"artifact_type": "etcd_state",
          "summary": f"{count} etcd record(s) — {breakdown}"})


def _excerpt(val, limit=400):
    if val is None:
        return ""
    if isinstance(val, (dict, list)):
        try:
            s = json.dumps(val, ensure_ascii=False, default=str)
        except Exception:
            s = str(val)
    else:
        s = str(val)
    return s if len(s) <= limit else s[:limit] + "…"


# ---- image_history (docker inspect / crane config / manifest.json) --------

def _flatten_manifest(obj, source):
    """Pull the layer history out of a config or inspect payload.

    Handles three common shapes:
      - ``docker inspect``: list of dicts, each with .Config.History (rare) or
        .RootFS + .Config; we use .History on the image config if present.
      - ``crane config`` / ``docker image inspect`` config: a single dict with
        ``history`` (list of {created, created_by, empty_layer}) and
        ``config`` (Cmd / Entrypoint / Env / User).
      - a saved image ``manifest.json``: list of [{Config, RepoTags, Layers}]
        where Config points at a <id>.json config file. We surface RepoTags +
        Layers; full history lives in the Config blob which may not be in the
        same directory, so we note its absence.
    """
    rows = []
    # case A: list of inspect records
    if isinstance(obj, list):
        for rec in obj:
            rows.extend(_flatten_manifest(rec, source))
        return rows
    if not isinstance(obj, dict):
        return rows

    # docker inspect record: image config under .Config, history under .History
    history = obj.get("history")
    config = obj.get("config") or obj.get("Config")
    repotags = obj.get("RepoTags") or obj.get("repoTags") or []

    # saved-image manifest entry: {Config: "<id>.json", RepoTags, Layers}
    if history is None and ("Layers" in obj or "Layers" in obj.get("Config", {}) if isinstance(obj.get("Config"), dict) else False):
        layers = obj.get("Layers") or []
        rows.append({
            "artifact_type": "image_history",
            "source": source,
            "repo_tags": repotags,
            "kind": "manifest_entry",
            "layers": layers,
            "note": ("full config history in separate blob: " + str(obj.get("Config"))
                     if obj.get("Config") else "config blob not referenced"),
        })
        return rows

    env = user = entrypoint = cmd = working_dir = ""
    if isinstance(config, dict):
        env = config.get("Env") or config.get("env") or []
        user = config.get("User") or config.get("user") or ""
        entrypoint = config.get("Entrypoint") or config.get("entrypoint") or []
        cmd = config.get("Cmd") or config.get("cmd") or []
        working_dir = config.get("WorkingDir") or config.get("workingDir") or ""

    # one row per history entry — created_by is the RUN/COPY/ADD instruction
    if isinstance(history, list) and history:
        for i, h in enumerate(history):
            if not isinstance(h, dict):
                continue
            rows.append({
                "artifact_type": "image_history",
                "source": source,
                "repo_tags": repotags,
                "index": i,
                "created": h.get("created", ""),
                "created_by": h.get("created_by", ""),
                "empty_layer": h.get("empty_layer", False),
                "comment": h.get("comment", ""),
                "author": h.get("author", ""),
                "config_user": user,
                "config_entrypoint": entrypoint,
                "config_cmd": cmd,
                "config_env": env,
                "config_workingdir": working_dir,
            })
        return rows

    # fallback: surface config + rootfs without per-layer history
    rootfs = obj.get("rootfs") or obj.get("RootFS") or {}
    rows.append({
        "artifact_type": "image_history",
        "source": source,
        "repo_tags": repotags,
        "kind": "config_only",
        "config_user": user,
        "config_entrypoint": entrypoint,
        "config_cmd": cmd,
        "config_env": env,
        "config_workingdir": working_dir,
        "layers": rootfs.get("layers", []) if isinstance(rootfs, dict) else [],
    })
    return rows


def parse_image_history(target):
    files = []
    if target and os.path.isfile(target):
        files = [target]
    else:
        names = ("config.json", "manifest.json", "image-config.json",
                 "image.json", "inspect.json")
        files = discover(target, names=names, exts=(".json",))
        # drop the generic manifest.json entries that are clearly OCI layout
        # index files (no Config/Layers/history) — we'll re-skip in the parser.
    rows = 0
    for p in files:
        txt = read_text(p)
        if not txt.strip():
            continue
        try:
            obj = json.loads(txt)
        except Exception as e:
            emit({"artifact_type": "image_history", "source": os.path.basename(p),
                  "error": f"json parse: {e}"})
            continue
        produced = _flatten_manifest(obj, os.path.basename(p))
        for r in produced:
            emit(r)
            rows += 1
    emit({"artifact_type": "image_history",
          "summary": f"{rows} history/config row(s) across {len(files)} file(s)"})


# ---- runtime_events (Falco / Tetragon / Sysdig / CRI JSONL) ---------------

def parse_runtime_events(target):
    paths = []
    if target and os.path.isfile(target):
        paths = [target]
    else:
        names = ("falco.log", "falco.jsonl", "falco_events.jsonl",
                 "tetragon.jsonl", "tetragon_events.jsonl",
                 "sysdig.jsonl", "cri_events.jsonl")
        paths = discover(target, names=names, exts=(".jsonl", ".log"))
        seen = set(); ordered = []
        for p in paths:
            if p not in seen:
                seen.add(p); ordered.append(p)
        paths = ordered

    count = 0
    for p, obj in each_json_line(paths):
        if "raw" in obj and len(obj) == 1:
            continue
        # Normalize across Falco / Tetragon / Sysdig field naming.
        rule = (obj.get("rule") or obj.get("RuleName") or
                obj.get("eventName") or obj.get("rule_name") or "")
        sev = (obj.get("priority") or obj.get("severity") or
               obj.get("Priority") or obj.get("level") or "")
        ts = (obj.get("time") or obj.get("timestamp") or
              obj.get("@timestamp") or obj.get("Time") or "")
        output = obj.get("output") or obj.get("Output") or obj.get("message") or ""
        # container / pod enrichment
        cont = obj.get("container") or {}
        if not isinstance(cont, dict):
            cont = {"id": cont}
        k8s = obj.get("kubernetes") or obj.get("k8s") or {}
        if not isinstance(k8s, dict):
            k8s = {}
        # Falco fields are sometimes nested; pull common ones defensively.
        proc = obj.get("proc") or {}
        if not isinstance(proc, dict):
            proc = {}
        emit({
            "artifact_type": "runtime_events",
            "source": os.path.basename(p),
            "timestamp": ts,
            "rule": rule,
            "severity": sev,
            "output": output[:1000] if isinstance(output, str) else "",
            "container_id": cont.get("id") or cont.get("container_id") or "",
            "container_name": cont.get("name") or "",
            "image": cont.get("image") or cont.get("image.repository") or "",
            "pod": k8s.get("pod") or k8s.get("pod_name") or "",
            "namespace": k8s.get("ns") or k8s.get("namespace") or "",
            "proc_name": proc.get("name") or proc.get("exepath") or "",
            "proc_cmdline": proc.get("cmdline") or "",
            "user": proc.get("user") or obj.get("user", ""),
            "raw": json.dumps(obj, ensure_ascii=False, default=str)[:800],
        })
        count += 1
    emit({"artifact_type": "runtime_events",
          "summary": f"{count} runtime detection(s) across {len(paths)} file(s)"})


# ---- network_policy (Calico / Cilium / k8s YAML+JSON manifests) -----------

def _split_yaml_docs(txt):
    """Split a multi-doc YAML stream on ``\\n---\\n`` lines."""
    docs = re.split(r'(?m)^---\s*$', txt)
    return [d for d in docs if d.strip()]


def _parse_yaml_lite(text):
    """A deliberately small YAML-ish parser for NetworkPolicy manifests.

    We only need enough to pull kind, metadata.name, metadata.namespace, and
    the podSelector / policyTypes / ingress / egress structure. If real YAML
    is available in the image we'd use it, but stdlib python has none — this
    best-effort parser handles the manifest shapes responders actually export.
    """
    import re as _re
    root = {"_lines": text.splitlines()}
    # kind / apiVersion (top-level scalars)
    kind = apiVersion = ""
    name = namespace = ""
    for line in root["_lines"]:
        s = line.strip()
        if s.startswith("kind:"):
            kind = s.split(":", 1)[1].strip().strip('"').strip("'")
        elif s.startswith("apiVersion:"):
            apiVersion = s.split(":", 1)[1].strip()
        elif s.startswith("name:") and not name:
            name = s.split(":", 1)[1].strip().strip('"').strip("'")
        elif s.startswith("namespace:") and not namespace:
            namespace = s.split(":", 1)[1].strip().strip('"').strip("'")
    return {"apiVersion": apiVersion, "kind": kind,
            "name": name, "namespace": namespace, "raw_excerpt": text[:600]}


def parse_network_policy(target):
    files = []
    if target and os.path.isfile(target):
        files = [target]
    else:
        names = ()
        # Calico: *.yaml; Cilium: networkpolicy / cnp; k8s: NetworkPolicy YAML
        files = discover(target, names=names, exts=(".yaml", ".yml", ".json"))
        # keep only things that look policy-related by name
        kept = [p for p in files if re.search(
            r"(networkpolic|network-polic|netpol|cnp|ciliumnetworkpolic|gnp|globalnetwork)",
            p.lower())]
        if not kept:
            kept = files  # if nothing matches the heuristic, try all yaml/json

    count = 0
    for p in kept:
        fl = p.lower()
        if fl.endswith(".json"):
            txt = read_text(p)
            try:
                obj = json.loads(txt)
            except Exception:
                continue
            docs = obj if isinstance(obj, list) else [obj]
            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                emit(_np_row_from_dict(doc, os.path.basename(p)))
                count += 1
        else:
            txt = read_text(p)
            for doc_txt in _split_yaml_docs(txt):
                try:
                    import yaml  # type: ignore
                    doc = yaml.safe_load(doc_txt)
                    if isinstance(doc, dict):
                        emit(_np_row_from_dict(doc, os.path.basename(p)))
                        count += 1
                        continue
                except Exception:
                    pass
                parsed = _parse_yaml_lite(doc_txt)
                if parsed.get("kind"):
                    emit({
                        "artifact_type": "network_policy",
                        "source": os.path.basename(p),
                        "kind": parsed["kind"],
                        "name": parsed["name"],
                        "namespace": parsed["namespace"],
                        "apiVersion": parsed["apiVersion"],
                        "raw_excerpt": parsed["raw_excerpt"],
                    })
                    count += 1
    emit({"artifact_type": "network_policy",
          "summary": f"{count} policy manifest(s) across {len(kept)} file(s)"})


def _np_row_from_dict(doc, source):
    meta = doc.get("metadata") or {}
    spec = doc.get("spec") or {}
    def _names(block):
        if not block:
            return []
        out = []
        for peer in block:
            if isinstance(peer, dict):
                pod = peer.get("podSelector") or {}
                ns_sel = peer.get("namespaceSelector")
                if peer.get("podSelector") is not None:
                    out.append({"podSelector": pod})
                if ns_sel is not None:
                    out.append({"namespaceSelector": ns_sel})
                if "ipBlock" in peer:
                    out.append({"ipBlock": peer["ipBlock"]})
        return out
    return {
        "artifact_type": "network_policy",
        "source": source,
        "apiVersion": doc.get("apiVersion", ""),
        "kind": doc.get("kind", ""),
        "name": meta.get("name", ""),
        "namespace": meta.get("namespace", ""),
        "policyTypes": spec.get("policyTypes", []),
        "podSelector": spec.get("podSelector", {}),
        "ingress_peers": _names(spec.get("ingress")) if isinstance(spec.get("ingress"), list) else [],
        "egress_peers": _names(spec.get("egress")) if isinstance(spec.get("egress"), list) else [],
    }


# ---- dispatch ------------------------------------------------------------

def main():
    if fmt == "audit_log":
        parse_audit_log(target)
    elif fmt == "pod_logs":
        parse_pod_logs(target)
    elif fmt == "kubelet_logs":
        parse_kubelet_logs(target)
    elif fmt == "etcd_state":
        parse_etcd_state(target)
    elif fmt == "image_history":
        parse_image_history(target)
    elif fmt == "runtime_events":
        parse_runtime_events(target)
    elif fmt == "network_policy":
        parse_network_policy(target)
    else:
        emit({"error": f"unknown artifact_type {fmt!r}"})

main()
'''


def _build_command(artifact_type: str, sub: str) -> list[str]:
    """Build the container argv: python3 -c '<parser>' <type> <target>."""
    target = f"/evidence/{sub}".rstrip("/") if sub else ""
    return [
        "python3", "-c", _PARSER, artifact_type, target,
    ]


# ---------------------------------------------------------------------------
# Output hash helper (mirrors chainsaw / aleapp_parse)
# ---------------------------------------------------------------------------


def _hash_file(p: Path) -> str | None:
    if not p.exists():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


class K8sParseTool(Tool):
    """Wrap the Kubernetes / container artifact-parsing toolchain (python3
    ``json`` / stdlib) inside ``svetovid/base``. Mirrors ALEAPP's artifact-
    coverage shape but for k8s audit logs, pod log dirs, etcd snapshots,
    container image manifests, and runtime detections — with zero non-stdlib
    dependencies so it runs anywhere the base image runs."""

    name = "k8s_parse"
    image = "svetovid/base"
    description = (
        "Parse a Kubernetes / container forensic artifact into structured "
        "rows. Pick artifact_type by what you triaged: audit_log (k8s API "
        "audit JSONL → API-call timeline), pod_logs (/var/log/pods/ tree → "
        "container output), kubelet_logs (container lifecycle), etcd_state "
        "(exported keyspace → cluster config / RBAC / secrets refs, "
        "read-only), image_history (docker/crane config or manifest.json → "
        "layer commands for supply-chain tampering), runtime_events "
        "(Falco/Tetragon/Sysdig JSONL → escape / privilege detections), "
        "network_policy (NetworkPolicy YAML/JSON → namespace egress / "
        "lateral-movement surface). Runs read-only over /evidence."
    )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "artifact_type": {
                    "type": "string",
                    "enum": list(ARTIFACT_TYPES.keys()),
                    "description": "Which Kubernetes / container artifact to parse.",
                },
                "evidence_subpath": {
                    "type": "string",
                    "description": (
                        "Subpath under /evidence to the artifact file or "
                        "directory. If omitted, the parser discovers the "
                        "canonical location (e.g. /var/log/pods/, "
                        "*audit*.log, an etcd export) under /evidence."
                    ),
                },
            },
            "required": ["artifact_type"],
        }

    async def invoke(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        from ..sandbox.docker_runner import run_in_sandbox

        call_id = ctx.make_call_id()
        atype = args.get("artifact_type", "")
        sub = args.get("evidence_subpath", "") or ""

        if atype not in ARTIFACT_TYPES:
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=2, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"unknown artifact_type {atype!r}; pick from {list(ARTIFACT_TYPES)}",
            )

        cmd = _build_command(atype, sub)

        ctx.bus.publish(E.tool_start(
            ctx.investigation_id, tool=self.name, args=args,
            sandboxed=True, container_id=None,
        ))
        ctx.bus.publish(E.agent_action(ctx.investigation_id, tool=self.name, args=args))

        # Capture stdout lines so we can persist a provenance copy AND parse
        # them into structured rows. (Mirrors aleapp_parse / linux_logs.)
        stdout_lines: list[str] = []

        def on_stdout(line: str) -> None:
            stdout_lines.append(line)
            ctx.bus.publish(E.tool_stdout(ctx.investigation_id, call_id, line))

        def on_stderr(line: str) -> None:
            ctx.bus.publish(E.tool_stderr(ctx.investigation_id, call_id, line))

        try:
            res = await run_in_sandbox(
                image=self.image or "",
                command=cmd,
                evidence_path=ctx.evidence_path,
                output_dir=ctx.output_dir,
                investigation_id=ctx.investigation_id,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
                host_fallback=True,
            )
        except Exception as e:
            ctx.bus.publish(E.error_event(
                ctx.investigation_id, f"k8s_parse ({atype}) failed: {e}"))
            return ToolResult(
                call_id=call_id, tool=self.name, exit_code=-1, duration_s=0.0,
                output_hash=None, output_path=None,
                summary=f"k8s_parse ({atype}) failed: {e}",
            )

        # The parser emits JSONL to stdout. Persist a local copy (provenance +
        # output_hash) and parse the rows into structured data.
        local_out = Path(ctx.output_dir) / f"k8s_{atype}.jsonl"
        if stdout_lines:
            try:
                local_out.write_text("\n".join(stdout_lines) + "\n", encoding="utf-8")
            except Exception:
                pass

        rows: list[dict[str, Any]] = []
        for line in stdout_lines:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line})
        rows = rows[:2000]

        output_hash = _hash_file(local_out)
        if rows:
            summary = f"k8s_parse ({atype}): {len(rows)} row(s)"
        else:
            summary = (
                f"k8s_parse ({atype}) exited {res.exit_code} "
                "but produced no JSONL output"
            )

        ctx.bus.publish(E.tool_end(
            ctx.investigation_id, call_id, res.exit_code, res.duration_s, output_hash,
        ))
        ctx.bus.publish(E.agent_observation(
            ctx.investigation_id, tool=self.name, summary=summary,
        ))
        ctx.bus.publish(E.provenance_recorded(ctx.investigation_id, {
            "tool": self.name,
            "image": self.image,
            "args": args,
            "exit_code": res.exit_code,
            "duration_s": res.duration_s,
            "output_hash": output_hash,
            "ts": E._now_iso(),
        }))

        return ToolResult(
            call_id=call_id, tool=self.name, exit_code=res.exit_code,
            duration_s=res.duration_s, output_hash=output_hash,
            output_path=str(local_out) if local_out.exists() else None,
            summary=summary, data={"artifact_type": atype, "rows": rows},
        )


# Module-level instance for tool enumeration parity with the other wrappers.
tool = K8sParseTool()
