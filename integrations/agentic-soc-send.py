#!/usr/bin/env python3
"""
Wazuh integration: receive a JSON alert, optionally enrich via OpenClaw,
# then email a SOC digest via reports@bedimsecurity.com.
#
# Created 2026-08-04 by Ciceron.
# - Receives alert JSON on stdin
# - Sends to OpenClaw (when reachable) for a 2-4 sentence narrative
# - Mails recipient via STARTTLS 587 to mail.example.com
#
# Required config (bind-mounted from /home/soc/.openclaw/workspace/secrets/):
#   /etc/reports-mailbox.env  -> contains REPORTS_MAILBOX, REPORTS_MAILBOX_PW,
#                                           SMTP_HOST, SMTP_PORT
#
# Optional env (override via env or via /etc/environment):
#   WAZUH_AGENTIC_ENABLE=1      (default 1; set 0 to skip the AI narrative step)
#   WAZUH_REPORTS_RECIPIENT     (default wes@example.com)
#   WAZUH_NOISE_DENYLIST        (default 1; set 0 to bypass the noise filter)
#   WAZUH_NOISE_LOG_DROPPED     (default 1; set 0 to silence the per-drop log)
#   WAZUH_NOISE_UNITS           (default: gms-mock-ui,gms-chrome,gitlab-runner;
#                                comma-separated systemd unit basenames; empty
#                                disables the per-unit filter. Used to drop
#                                alerts from known-dead services that have
#                                been disabled on the host but keep emitting
#                                journal lines from a half-cleaned state.)
"""
import os
import sys
import json
import time
import subprocess
import smtplib
import ssl
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid


# ---------------------------------------------------------------------------
# SOC 2.5 (2026-08-05): Noisy-rule denylist.
#
# Empirical analysis: 33,142 alerts in last 7 days; top 11 rules = 95% of
# volume. These 9 IDs are operational noise (mailcow container cycling,
# boot agent lifecycle, sshd connection-reset, PAM session open/close,
# SCA-passed). For each, exit_code=0 + no email + no OpenClaw call.
#
# Why not Wazuh-level suppression? `local_rules.xml` redefinitions with
# level=0 don't work in Wazuh 4.14 (engine uses MAX-of-matching-rules; the
# ruleset's level-N wins). `alert_by_email=no` is the same story. The only
# reliable place to drop these BEFORE they cost cycles is here.
#
# Reference: docs/soc/noisy-rule-suppression-2026-08-05.md
# ---------------------------------------------------------------------------
NOISY_RULE_IDS = frozenset({
    40704,  # L5  systemd: service exited due to failure (mailcow cycling)
    503,    # L3  Wazuh agent started (boot noise)
    506,    # L3  Wazuh agent stopped (boot noise)
    533,    # L7  Listened ports (netstat) changed (mailcow cycling)
    5740,   # L4  sshd: connection reset by peer
    5762,   # L4  sshd: connection reset
    5501,   # L3  PAM: login session opened
    5502,   # L3  PAM: login session closed
    19008,  # L3  SCA passed (compliance spam)
})

# SOC 2.5b (2026-08-09): Per-systemd-unit denylist. Some services are
# intentionally disabled on the host (unit moved to
# /etc/systemd/disabled-by-soc-2026-08-09/) but if they were running
# before the disable, systemd may still flush journal lines that
# mention them — wazuh picks those up and emits rule 40704 (or
# others) for them. Without this filter we'd be back to 9,000+
# 40704s/day within an hour of anyone re-enabling a dead unit.
#
# Defaults to the three units we know about from 2026-08-09 cleanup
# on darth. Override via WAZUH_NOISE_UNITS env var (comma-separated
# basenames, no .service suffix). Empty string disables the filter.
DEFAULT_NOISY_UNITS = frozenset({
    "gms-mock-ui",     # darth — Express 5 / path-to-regexp v8 broken
    "gms-chrome",      # darth — Chrome kiosk for gms-mock-ui
    "gitlab-runner",   # darth — config.toml permission denied (Trooper2)
})


def _load_noisy_units():
    """Return the set of systemd unit basenames to denylist.

    Reads WAZUH_NOISE_UNITS env var (comma-separated). Falls back to
    DEFAULT_NOISY_UNITS when unset/empty. Always returns a frozenset
    for O(1) membership checks.
    """
    raw = os.environ.get("WAZUH_NOISE_UNITS", "")
    if not raw:
        return DEFAULT_NOISY_UNITS
    return frozenset(s.strip() for s in raw.split(",") if s.strip())

def realtime_ingest(alert):
    """SOC 1.1: push the alert to the local real-time SOC ingest server.

    Fast fail (200ms timeout). Server is on 127.0.0.1:8765 by default
    (realtime-soc-server.service). Returns nothing on success; logs +
    silently swallows failures so the email pipeline is not blocked.

    Behavior:
      - Disabled by default? No — enabled by default. The whole point of
        SOC 1.1 is to get the alert into the agent in real time.
      - Set REALTIME_SOC_DISABLED=1 to bypass (e.g. for the selftest
        harness that doesn't want a side effect).
      - Set REALTIME_SOC_URL to override host:port.
    """
    if os.environ.get("REALTIME_SOC_DISABLED", "0") == "1":
        return None
    url = os.environ.get("REALTIME_SOC_URL", "http://127.0.0.1:8765/ingest")
    try:
        data = json.dumps(alert).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        ingest_started = time.monotonic()
        with urllib.request.urlopen(req, timeout=0.2) as resp:
            elapsed_ms = round((time.monotonic() - ingest_started) * 1000.0, 1)
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status != 200:
                _REALTIME_LOG.warning("realtime soc non-200: %s — %s",
                                      resp.status, body[:200])
                return None
            try:
                j = json.loads(body)
            except Exception:
                return None
            _REALTIME_LOG.info(
                "realtime soc ingest: ok=%s elapsed=%sms new_alert=%s new_incident=%s",
                j.get("ok"),
                j.get("elapsed_ms"),
                j.get("new_alert_ids"),
                j.get("new_incident_ids"),
            )
            # SOC 1.1 measurement: log total client-side latency including
            # connection setup + serialization. Used in the done-when test.
            sys.stderr.write(
                f"[soc-1.1] realtime_ingest client_total_ms={elapsed_ms} "
                f"server_elapsed_ms={j.get('elapsed_ms')} "
                f"new_incident_ids={j.get('new_incident_ids')}\n"
            )
            return j
    except urllib.error.URLError as e:
        # Most common: server not running. Fail soft — the email path is
        # still the primary delivery mechanism.
        _REALTIME_LOG.info("realtime soc unavailable (%s); continuing to email", e)
        return None
    except Exception as e:
        _REALTIME_LOG.warning("realtime soc unexpected error: %s", e)
        return None


_NOISE_LOG = logging.getLogger("agentic-soc-send.noise")
_REALTIME_LOG = logging.getLogger("agentic-soc-send.realtime")


def is_noisy(alert):
    """SOC 2.5: return True if this alert is in the operational-noise denylist.

    Two-layer filter:
      1. Rule-ID denylist (NOISY_RULE_IDS) — coarse, by Wazuh rule ID.
      2. Per-systemd-unit denylist (DEFAULT_NOISY_UNITS / WAZUH_NOISE_UNITS)
         — fine, by the systemd unit basename mentioned in the alert's
         full_log (or data.systemd.unit if a custom decoder emits it).

    Both layers can be independently disabled via env:
      WAZUH_NOISE_DENYLIST=0  -> bypass both
      WAZUH_NOISE_UNITS=""    -> bypass only the per-unit layer
    """
    if os.environ.get("WAZUH_NOISE_DENYLIST", "1") != "1":
        return False
    rule = alert.get("rule") or {}
    try:
        rid = int(rule.get("id", 0))
    except (TypeError, ValueError):
        rid = 0
    if rid in NOISY_RULE_IDS:
        return True
    # Per-unit filter: only meaningful for rule 40704 (systemd: Service
    # exited due to a failure), but harmless for other rules — the unit
    # name appears in the journal line and a noisy unit's name won't
    # appear in unrelated alerts.
    noisy_units = _load_noisy_units()
    if not noisy_units:
        return False
    unit_name = _extract_systemd_unit(alert)
    if unit_name and unit_name in noisy_units:
        return True
    return False


_SYSTEMD_UNIT_RE = None


def _extract_systemd_unit(alert):
    """Return the systemd unit basename mentioned in the alert, or None.

    Looks in this order:
      1. `data.systemd.unit` — emitted by a custom systemd decoder
         (none today, but reserved for future-proofing).
      2. `full_log` — the raw journal line, e.g.
         "host systemd[1]: gms-mock-ui.service: Main process exited, ..."
         We extract the first `.service` (or `.target` / `.socket` /
         `.mount`) token from the line and strip the suffix.

    Returns just the basename ("gms-mock-ui"), no ".service" suffix,
    so callers can compare against a set of bare unit basenames.
    """
    global _SYSTEMD_UNIT_RE
    data = alert.get("data") or {}
    unit = data.get("systemd.unit")
    if isinstance(unit, str) and unit:
        return unit.split(".", 1)[0]
    full_log = alert.get("full_log", "") or ""
    if not full_log:
        return None
    if _SYSTEMD_UNIT_RE is None:
        import re as _re
        # Match the first token that ends in .service/.target/.socket/
        # .mount/.timer/.path before the next whitespace/colon/comma.
        _SYSTEMD_UNIT_RE = _re.compile(
            r"\b([A-Za-z0-9_.@:-]+?\.(?:service|target|socket|mount|timer|path))\b"
        )
    m = _SYSTEMD_UNIT_RE.search(full_log)
    if not m:
        return None
    return m.group(1).split(".", 1)[0]


def load_env_file():
    ENVFILE = os.environ.get("WAZUH_REPORTS_ENV", "/etc/reports-mailbox.env")
    if not os.path.exists(ENVFILE):
        sys.stderr.write(f"missing env file: {ENVFILE}\n")
        sys.exit(1)
    for line in open(ENVFILE):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def maybe_enrich(alert):
    """SOC A1 (2026-08-06): use openclaw agent harness via llm_runtime.

    Previous version invoked `openclaw ask`, which does NOT exist in
    OpenClaw 2026.7.1 — the email narrative was silently skipped.
    Replaced with a structured `openclaw agent --agent soc-narrator`
    call routed through the shared `llm_runtime.py` helper. Falls
    back gracefully on any LLM failure (sets
    `agentic_narrative_error` so the email still goes out with the
    raw alert).
    """
    if os.environ.get("WAZUH_AGENTIC_ENABLE", "1") != "1":
        return alert
    # Allow per-tenant / per-deploy runtime override.
    runtime = os.environ.get("SOC_LLM_RUNTIME", "openclaw")
    agent_id = os.environ.get("WAZUH_NARRATOR_AGENT", "soc-narrator")
    try:
        from llm_runtime import call_llm  # type: ignore
    except ImportError:
        # llm_runtime is in scripts/soc/. When the integration script runs
        # inside the Wazuh manager container, that path is bind-mounted
        # at /home/soc/repos/example-work/scripts/soc/ (or wherever the
        # container's compose file points). For the manager container we
        # preinstall the file at /usr/local/share/soc/llm_runtime.py.
        candidates = [
            "/usr/local/share/soc/llm_runtime.py",
            "/home/soc/repos/example-work/scripts/soc/llm_runtime.py",
        ]
        import importlib.util
        loaded = False
        for c in candidates:
            if os.path.exists(c):
                # IMPORTANT: register in sys.modules BEFORE exec_module.
                # Python 3.9's dataclasses need to look up the module
                # via sys.modules; without this, `@dataclass` raises
                # AttributeError: 'NoneType' object has no attribute
                # '__dict__' when it tries to resolve the type hints.
                spec = importlib.util.spec_from_file_location("llm_runtime", c)
                mod = importlib.util.module_from_spec(spec)
                sys.modules["llm_runtime"] = mod
                spec.loader.exec_module(mod)
                loaded = True
                break
        if not loaded:
            alert["agentic_narrative_error"] = (
                "llm_runtime.py not found; checked "
                + ", ".join(candidates)
            )
            return alert
        from llm_runtime import call_llm  # type: ignore

    prompt = (
        "Write a 2-4 sentence SOC analyst summary of the following Wazuh alert. "
        "State severity (low / medium / high / critical), what happened, the "
        "recommended next action. Plain text, no markdown headers.\n\n"
        "ALERT JSON:\n" + json.dumps(alert, indent=2)[:3000]
    )
    resp = call_llm(
        runtime=runtime,
        agent_id=agent_id,
        message=prompt,
        system="You are a SOC analyst. Be terse and actionable.",
        timeout=25.0,
        # Track B, B2 (2026-08-07): attach the alert as the audit input
        # so the audit row's input_hash + input_summary are populated
        # automatically. The hash ties this record to the full alert
        # without writing the alert (with PII) into the audit log.
        audit_input=alert,
        audit_input_kind="wazuh_alert",
        audit_input_summary=(
            f"L{(alert.get('rule') or {}).get('level', '?')} "
            f"{(alert.get('rule') or {}).get('id', '?')} "
            f"{(alert.get('agent') or {}).get('name', '?')}"
        ),
    )
    if resp.ok and resp.text:
        alert["agentic_narrative"] = resp.text
        if resp.run_id:
            alert["agentic_run_id"] = resp.run_id
        if resp.model:
            alert["agentic_model"] = resp.model
        if resp.duration_ms is not None:
            alert["agentic_duration_ms"] = resp.duration_ms
    else:
        alert["agentic_narrative_error"] = (
            resp.error or "unknown llm_runtime error"
        )
        # SOC 1.1 timing — still log the realtime ingest call regardless.
    return alert



# ---------------------------------------------------------------------------
# SOC A3 (2026-08-09): memory MCP bridge. Lazy-starts the
# soc-memory-mcp server inside the manager container, then queries
# it for prior incident context that should reach soc-triage's
# decision prompt. Without this, soc-triage hallucinates 'Memory
# search still disabled (index metadata missing)' instead of citing
# real prior incidents.
#
# The MCP is bound to 127.0.0.1:8770 (loopback only by design). The
# integration daemon runs inside the manager container, so
# 127.0.0.1 = container loopback, which is fine because the MCP also
# runs inside the container.
#
# The MCP backing JSONL lives at /var/ossec/logs/soc-memory.jsonl
# so the wazuh user (uid 999) can both read + write it. The
# /var/ossec/logs directory is a docker volume bind-mounted into the
# container as wazuh:wazuh (mode 0770).
# ---------------------------------------------------------------------------

SOC_MEMORY_MCP_HOST = os.environ.get("SOC_MEMORY_MCP_HOST", "127.0.0.1")
SOC_MEMORY_MCP_PORT = int(os.environ.get("SOC_MEMORY_MCP_PORT", "8770"))
SOC_MEMORY_MCP_URL = f"http://{SOC_MEMORY_MCP_HOST}:{SOC_MEMORY_MCP_PORT}"
SOC_MEMORY_MCP_SCRIPT = "/usr/local/share/soc/soc-memory-mcp/server.py"
SOC_MEMORY_FILE = os.environ.get(
    "SOC_MEMORY_FILE",
    "/var/ossec/logs/soc-memory.jsonl",
)
# Set to 0 to skip the memory MCP entirely (e.g. during local debug).
SOC_MEMORY_MCP_ENABLE = os.environ.get("SOC_MEMORY_MCP_ENABLE", "1") == "1"

DEBUG_LOG_PATH = "/var/ossec/logs/soc-memory-mcp-debug.log"

def _dbg(msg):
    """Append a debug line to the MCP debug log. Best-effort."""
    try:
        with open(DEBUG_LOG_PATH, "a") as f:
            f.write(str(msg) + chr(10))
    except Exception:
        pass

def _port_listening(host, port, timeout=0.5):
    """Return True if (host, port) has a TCP listener."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False

def _ensure_memory_mcp_running():
    """Start the soc-memory-mcp server inside the manager container if
    it isn't already running. Idempotent.
    Returns True if the MCP is listening on its port after this call.
    """
    if not SOC_MEMORY_MCP_ENABLE:
        return False
    if _port_listening(SOC_MEMORY_MCP_HOST, SOC_MEMORY_MCP_PORT):
        return True
    if not os.path.exists(SOC_MEMORY_MCP_SCRIPT):
        _dbg("script missing: " + SOC_MEMORY_MCP_SCRIPT)
        return False
    try:
        Path(SOC_MEMORY_FILE).parent.mkdir(parents=True, exist_ok=True)
        log_file = "/var/ossec/logs/soc-memory-mcp.log"
        _dbg("spawning (file=" + SOC_MEMORY_FILE + ")")
        subprocess.Popen(
            ["/usr/bin/python3", SOC_MEMORY_MCP_SCRIPT],
            stdout=open(log_file, "ab"),
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env={**os.environ,
                 "SOC_MEMORY_FILE": SOC_MEMORY_FILE,
                 "PYTHONUNBUFFERED": "1"},
        )
        for _ in range(20):
            time.sleep(0.1)
            if _port_listening(SOC_MEMORY_MCP_HOST, SOC_MEMORY_MCP_PORT):
                _dbg("listening on port")
                return True
        _dbg("FAILED to bind port")
        return False
    except Exception as e:
        _dbg("launch crashed: " + type(e).__name__ + ": " + str(e))
        return False

def _memory_search_for_alert(alert, top_k=5):
    """Query the memory MCP for prior incidents matching this alert."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    payload = {
        "tenant_id": os.environ.get("WAZUH_TENANT_ID", "bedimsecurity"),
        "rule_id": rule.get("id"),
        "agent": agent.get("name"),
        "srcip": data.get("srcip"),
        "top_k": top_k,
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        req = urllib.request.Request(
            f"{SOC_MEMORY_MCP_URL}/tools/memory_search",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            j = json.loads(resp.read().decode("utf-8"))
            return j.get("matches") or []
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, OSError):
        return []

def _memory_add_incident(alert, decision):
    """Append the just-decided incident to memory (idempotent)."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    incident_id = (alert.get("_soc_incident_id")
                   or alert.get("agentic_decision", {}).get("incident_id"))
    if not incident_id:
        return
    payload = {
        "tenant_id": os.environ.get("WAZUH_TENANT_ID", "bedimsecurity"),
        "incident_id": str(incident_id),
        "summary": (
            f"Rule {rule.get('id')} on host {agent.get('name', '?')}: "
            f"{rule.get('description', '?')[:120]}. "
            f"Decision: severity_class={decision.get('severity_class')}, "
            f"recommended_response={decision.get('recommended_response')}, "
            f"confidence={decision.get('confidence')}"
        )[:2000],
        "rule_id": rule.get("id"),
        "agent": agent.get("name"),
        "srcip": data.get("srcip"),
        "ts": alert.get("timestamp") or datetime.now(timezone.utc).isoformat(),
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    try:
        req = urllib.request.Request(
            f"{SOC_MEMORY_MCP_URL}/tools/memory_add",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        pass

def _format_memory_for_prompt(matches):
    """Format MCP matches into a short paragraph the LLM can quote."""
    if not matches:
        return ""
    lines = []
    for m in matches[:3]:
        ts = (m.get("ts") or "")[:19]
        inc = m.get("incident_id", "?")
        rule = m.get("rule_id")
        agent = m.get("agent")
        srcip = m.get("srcip")
        summary = (m.get("summary") or "").strip()
        bits = [f"  - {ts} incident_id={inc}"]
        if rule is not None:
            bits.append(f"rule={rule}")
        if agent:
            bits.append(f"agent={agent}")
        if srcip:
            bits.append(f"srcip={srcip}")
        lines.append(" ".join(bits))
        if summary:
            lines.append(f"    summary: {summary[:300]}")
    return chr(10).join(lines)



def maybe_decide(alert):
    """SOC Track B / B1 (2026-08-07): invoke soc-triage's decision
    tool. Adds `agentic_decision` to the alert dict with the full
    Decision shape (severity_class, is_known_pattern,
    recommended_response, confidence, reasoning, low_confidence,
    run_id).

    SOC A3 (2026-08-09): before invoking the LLM, fetch prior
    incident context from the memory MCP and pass it as
    host_memory=. After the decision, append the new incident to
    memory so the next alert can cite THIS one.

    Failure mode: if the MCP is unreachable, we silently skip
    the search/add and the LLM gets the original prompt without
    host_memory. Email delivery is never blocked by MCP errors.

    Disabled with WAZUH_DECISION_ENABLE=0 (default 1).
    """
    if os.environ.get("WAZUH_DECISION_ENABLE", "1") != "1":
        return alert
    try:
        import importlib.util as _ilu
        candidates = [
            "/usr/local/share/soc/soc_decision.py",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "soc", "soc_decision.py"),
        ]
        decision_mod = None
        for c in candidates:
            c = os.path.abspath(c)
            if os.path.exists(c):
                spec = _ilu.spec_from_file_location("soc_decision", c)
                decision_mod = _ilu.module_from_spec(spec)
                sys.modules["soc_decision"] = decision_mod
                spec.loader.exec_module(decision_mod)
                break
        if decision_mod is None:
            alert["agentic_decision_error"] = (
                "soc_decision.py not found; checked " + ", ".join(candidates)
            )
            return alert

        # SOC A3 (2026-08-09): fetch prior incident context from the
        # memory MCP. Lazy-start it on first call.
        host_memory_str = ""
        mcp_matches = []
        if _ensure_memory_mcp_running():
            mcp_matches = _memory_search_for_alert(alert, top_k=5)
            host_memory_str = _format_memory_for_prompt(mcp_matches)
            alert["_soc_memory_matches"] = len(mcp_matches)
        else:
            alert["_soc_memory_matches"] = -1  # MCP unreachable

        tenant_id = os.environ.get("WAZUH_TENANT_ID")
        d = decision_mod.decide(
            alert,
            tenant_id=tenant_id,
            host_memory=host_memory_str or None,
        )
        alert["agentic_decision"] = d.to_dict()

        # SOC A3 (2026-08-09): write the just-decided incident to
        # memory so future alerts can cite it.
        if _port_listening(SOC_MEMORY_MCP_HOST, SOC_MEMORY_MCP_PORT):
            _memory_add_incident(alert, d.to_dict())

        return alert
    except Exception as e:
        alert["agentic_decision_error"] = "maybe_decide failed: " + repr(e)
        return alert


def build_email(alert, recipient):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    level = rule.get("level", 0)
    descr = rule.get("description", "alert")
    agent_name = agent.get("name", "?")
    rule_id = rule.get("id", "?")
    subject = f"[Wazuh L{level}] {agent_name} rule {rule_id}: {descr}"[:200]
    lines = []
    lines.append(f"Wazuh alert — level {level}")
    lines.append("")
    lines.append(f"Rule:     {rule_id} — {descr}")
    lines.append(f"Agent:    {agent_name} ({agent.get('ip', '?')})")
    lines.append(f"Time:     {alert.get('timestamp', '?')}")
    if alert.get("agentic_narrative"):
        lines.append("")
        lines.append("--- Analyst summary ---")
        lines.append(alert["agentic_narrative"])
    if alert.get("agentic_narrative_error"):
        lines.append("")
        lines.append(f"--- (analyst unavailable: {alert['agentic_narrative_error']}) ---")
    # SOC Track B / B1: the agent's decision (severity,
    # recommended response, confidence, reasoning)
    decision = alert.get("agentic_decision") or {}
    if decision:
        lines.append("")
        lines.append("--- Agent decision (Track B) ---")
        sev = decision.get("severity_class", "?")
        resp = decision.get("recommended_response", "?")
        conf = decision.get("confidence", 0.0)
        kp = "yes" if decision.get("is_known_pattern") else "no"
        lines.append(f"Severity class : {sev}")
        lines.append(f"Known pattern  : {kp}")
        lines.append(f"Recommended    : {resp}  (confidence {conf:.2f})")
        if decision.get("low_confidence"):
            lines.append("                ↳ low confidence — will be reviewed")
        if decision.get("reasoning"):
            lines.append("")
            lines.append(f"Reasoning: {decision['reasoning']}")
    if alert.get("agentic_decision_error"):
        lines.append("")
        lines.append(f"--- (decision unavailable: {alert['agentic_decision_error']}) ---")
    lines.append("")
    lines.append("--- Raw alert (truncated) ---")
    lines.append(json.dumps(alert, indent=2)[:3500])
    body = "\n".join(lines)
    return subject, body


def main():
    load_env_file()

    raw = sys.stdin.read()
    try:
        alert = json.loads(raw) if raw.strip() else {"_note": "empty alert"}
    except Exception as e:
        alert = {"_raw": raw[:1000], "_parse_error": str(e)}

    if isinstance(alert, list):
        # If a multi-alert payload comes through, treat as a single digest
        alert = {"_multi": alert, "rule": {"level": 10, "description": f"{len(alert)} alerts batch"},
                 "agent": {"name": "batch", "ip": "?"}, "timestamp": "?"}

    # SOC 2.5: drop operational noise before any costly work
    if is_noisy(alert):
        if os.environ.get("WAZUH_NOISE_LOG_DROPPED", "1") == "1":
            rule_id = (alert.get("rule") or {}).get("id", "?")
            agent_name = (alert.get("agent") or {}).get("name", "?")
            _NOISE_LOG.info("dropped noisy rule %s from agent %s", rule_id, agent_name)
        # NOTE: noisy alerts skip realtime_ingest too — they are operational
        # noise and the daily digest already covers them.
        return 0

    # SOC A1 (2026-08-06): enrich with the LLM narrative FIRST so the
    # realtime SOC JSONL record carries the narrative. The latency cost
    # is ~10-12s per alert (acceptable for L12+); for high-volume
    # operational-noise rules we already skip via the denylist above.
    alert = maybe_enrich(alert)

    # SOC Track B / B1 (2026-08-07): invoke the decision tool AFTER
    # the narrative so the JSONL record carries both. The decision
    # cost is ~5-10s; total per-alert latency stays around 15-22s
    # for L12+ alerts (which is the path that matters; noisy L<10
    # rules skip both via the denylist).
    alert = maybe_decide(alert)

    # SOC 1.1: real-time ingest into SecurityOperationsAgent AFTER the
    # enrichment so the JSONL record carries the agentic_narrative
    # fields. Fast-fail (200ms); an unavailable server does NOT block
    # email delivery.
    realtime_ingest(alert)
    recipient = os.environ.get("WAZUH_REPORTS_RECIPIENT", "wes@example.com")
    subject, body = build_email(alert, recipient)

    ctx = ssl.create_default_context()
    # The Wazuh manager container sets SSL_CERTIFICATE_AUTHORITIES
    # to its internal CA (for agent↔manager TLS). For OUTBOUND
    # SMTP to mail.example.com (Let's Encrypt), we need the
    # system CA bundle, not the Wazuh internal CA. Pick the first
    # one that exists; fall back to the default context.
    # NOTE: 'os' is imported at the top of the file; do NOT add a
    # function-local `import os` here or Python will treat every
    # `os.environ` reference as a local variable (UnboundLocalError).
    for cafile in ("/etc/ssl/certs/ca-certificates.crt",
                   "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.exists(cafile):
            ctx = ssl.create_default_context(cafile=cafile)
            break
    smtp_host = os.environ["SMTP_HOST"]
    smtp_port = int(os.environ["SMTP_PORT"])
    smtp_user = os.environ["REPORTS_MAILBOX"]
    smtp_pass = os.environ["REPORTS_MAILBOX_PW"]

    msg = MIMEText(body)
    msg["From"] = smtp_user
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="bedimsecurity.com")
    msg["X-Wazuh-Agent"] = (alert.get("agent") or {}).get("name", "?")
    msg["X-Wazuh-Level"] = str((alert.get("rule") or {}).get("level", 0))

    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
        s.starttls(context=ctx)
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write(f"FAIL: {e!r}\n")
        sys.exit(1)
