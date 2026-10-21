#!/usr/bin/env python3
"""
Created  by: ANISH R
Date: 2024-06-15
Version: 1.0
For any queries or suggestions, contact: anishry88@gmail.com ph: +91-9895 086 743
Developer: Anish R
Email:anishry88@gmail.com
Developer's Phone: +91-9895 086 743
Tool For CERT-K
-----------
Disclaimer:
-----------
This tool is intended for educational and ethical use only. The author is not responsible for any misuse
or damage caused by this software. Always obtain proper authorization before testing any website.

"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import sqlite3
import hashlib
import re
import json
import ssl
import socket
import smtplib
import time
import os
import html
import webbrowser
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional

# ─── palette ────────────────────────────────────────────
BG        = "#07080D"
BG_PANEL  = "#0B0E16"
BG_CARD   = "#0F1320"
BG_INPUT  = "#131929"
BG_ROW    = "#0A0C14"
BORDER    = "#1A2035"
ACCENT    = "#3B82F6"
GREEN     = "#10B981"
YELLOW    = "#F59E0B"
ORANGE    = "#F97316"
RED       = "#EF4444"
PURPLE    = "#8B5CF6"
CYAN      = "#06B6D4"
TEXT_PRI  = "#E2E8F0"
TEXT_SEC  = "#475569"
TEXT_MUT  = "#1E293B"
MONO      = ("Consolas", 10)

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     TEXT_SEC,
    "OK":       GREEN,
}

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watchdog.db")

# ════════════════════════════════════════════════════════
#  ATTACK DETECTION SIGNATURES
# ════════════════════════════════════════════════════════
DEFACEMENT_PATTERNS = [
    (r'hacked\s+by',                        "CRITICAL", "Defacement: 'hacked by' string detected"),
    (r'owned\s+by',                         "CRITICAL", "Defacement: 'owned by' string detected"),
    (r'pwned\s+by',                         "CRITICAL", "Defacement: 'pwned by' string detected"),
    (r'defaced\s+by',                       "CRITICAL", "Defacement: 'defaced by' string detected"),
    (r'r00ted\s+by',                        "CRITICAL", "Defacement: 'r00ted by' string detected"),
    (r'#team\w*',                           "HIGH",     "Defacement: hacker team tag detected"),
    (r'greetz\s+to',                        "HIGH",     "Defacement: 'greetz to' message detected"),
    (r'you\s+have\s+been\s+hacked',        "CRITICAL", "Defacement: explicit hack message"),
    (r'this\s+site\s+has\s+been\s+hacked', "CRITICAL", "Defacement: explicit hack message"),
    (r'hack3d',                             "HIGH",     "Defacement: leet-speak 'hack3d' detected"),
    (r'<h[1-3][^>]*>\s*error\s*</h',       "MEDIUM",   "Suspicious: error heading injected"),
]

MALWARE_PATTERNS = [
    (r'eval\s*\(\s*(?:base64_decode|atob|unescape|String\.fromCharCode)',
     "CRITICAL", "Malware: obfuscated eval() injection detected"),
    (r'document\.write\s*\(\s*unescape',
     "CRITICAL", "Malware: document.write+unescape injection"),
    (r'<script[^>]*>\s*(?:var|let|const)\s+\w+\s*=\s*["\'][A-Za-z0-9+/=]{60,}["\']',
     "HIGH",     "Malware: large base64 blob in inline script"),
    (r'coinhive|cryptonight|minero|coinminer|crypto-?loot|webminer',
     "CRITICAL", "Malware: crypto-mining script detected"),
    (r'<iframe[^>]+style=["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|'
     r'width\s*:\s*0|height\s*:\s*0)',
     "HIGH",     "Malware: hidden iframe injected"),
    (r'<script[^>]+src=["\']https?://(?!(?:cdnjs|ajax\.googleapis|code\.jquery|'
     r'cdn\.jsdelivr|unpkg\.com|fonts\.googleapis))[^"\']+["\']',
     "MEDIUM",   "Suspicious: external script from unknown domain"),
    (r'fromCharCode\s*\(\s*(?:\d+\s*,\s*){10,}',
     "HIGH",     "Malware: long fromCharCode() sequence (encoded payload)"),
    (r'(?:xss|<script>alert|javascript:alert)',
     "HIGH",     "Malware: XSS payload string detected"),
    (r'(?:union\s+select|drop\s+table|insert\s+into.*values)',
     "HIGH",     "Malware: SQL injection artifact in page content"),
    (r'(?:shell_exec|system\s*\(|passthru\s*\(|popen\s*\()',
     "CRITICAL", "Malware: PHP shell command artifact detected"),
    (r'<\?php',
     "CRITICAL", "Malware: Raw PHP tag in rendered HTML"),
    (r'document\.cookie\s*=.*?document\.location',
     "HIGH",     "Malware: cookie-stealing redirect script detected"),
]

PHISHING_PATTERNS = [
    (r'(?:enter\s+your\s+(?:credit\s+card|card\s+number|password|social\s+security))',
     "HIGH",  "Phishing: credential-harvesting prompt detected"),
    (r'(?:verify\s+your\s+(?:account|identity|paypal|bank))',
     "HIGH",  "Phishing: account verification scam pattern"),
    (r'(?:your\s+account\s+(?:has\s+been\s+)?(?:suspended|compromised|locked))',
     "MEDIUM","Phishing: account-lock scare message"),
]

ALL_PATTERNS = DEFACEMENT_PATTERNS + MALWARE_PATTERNS + PHISHING_PATTERNS


# ════════════════════════════════════════════════════════
#  DATABASE
# ════════════════════════════════════════════════════════
class Database:
    def __init__(self, path=DB_FILE):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sites (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                url          TEXT UNIQUE NOT NULL,
                label        TEXT DEFAULT '',
                interval_sec INTEGER DEFAULT 300,
                enabled      INTEGER DEFAULT 1,
                added_at     TEXT,
                last_check   TEXT,
                status       TEXT DEFAULT 'PENDING',
                risk         TEXT DEFAULT 'INFO'
            );
            CREATE TABLE IF NOT EXISTS baselines (
                site_id      INTEGER PRIMARY KEY,
                content_hash TEXT,
                title        TEXT,
                status_code  INTEGER,
                content_len  INTEGER,
                redirect_url TEXT,
                ssl_expiry   TEXT,
                ssl_fingerprint TEXT,
                ext_domains  TEXT,
                captured_at  TEXT,
                FOREIGN KEY(site_id) REFERENCES sites(id)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id      INTEGER,
                url          TEXT,
                severity     TEXT,
                category     TEXT,
                message      TEXT,
                detail       TEXT,
                ts           TEXT,
                acknowledged INTEGER DEFAULT 0,
                FOREIGN KEY(site_id) REFERENCES sites(id)
            );
            CREATE TABLE IF NOT EXISTS checks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id      INTEGER,
                ts           TEXT,
                status_code  INTEGER,
                content_hash TEXT,
                content_len  INTEGER,
                resp_ms      INTEGER,
                alert_count  INTEGER DEFAULT 0,
                FOREIGN KEY(site_id) REFERENCES sites(id)
            );
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            """)
            self.conn.commit()

    def q(self, sql, params=()):
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def fetch(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def fetchone(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def get_setting(self, key, default=""):
        row = self.fetchone("SELECT value FROM settings WHERE key=?", (key,))
        return row[0] if row else default

    def set_setting(self, key, value):
        self.q("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, value))

    def add_site(self, url, label="", interval=300):
        try:
            self.q(
                "INSERT INTO sites(url,label,interval_sec,added_at,status) "
                "VALUES(?,?,?,?,?)",
                (url, label or url, interval,
                 datetime.now().isoformat(timespec="seconds"), "PENDING")
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def get_sites(self):
        return self.fetch(
            "SELECT id,url,label,interval_sec,enabled,status,risk,"
            "last_check FROM sites ORDER BY id")

    def remove_site(self, site_id):
        self.q("DELETE FROM baselines WHERE site_id=?", (site_id,))
        self.q("DELETE FROM alerts    WHERE site_id=?", (site_id,))
        self.q("DELETE FROM checks    WHERE site_id=?", (site_id,))
        self.q("DELETE FROM sites     WHERE id=?",      (site_id,))

    def get_baseline(self, site_id):
        return self.fetchone(
            "SELECT content_hash,title,status_code,content_len,"
            "redirect_url,ssl_expiry,ssl_fingerprint,ext_domains,captured_at "
            "FROM baselines WHERE site_id=?", (site_id,))

    def save_baseline(self, site_id, b: dict):
        self.q(
            "INSERT OR REPLACE INTO baselines VALUES(?,?,?,?,?,?,?,?,?,?)",
            (site_id, b["content_hash"], b["title"], b["status_code"],
             b["content_len"], b["redirect_url"], b["ssl_expiry"],
             b["ssl_fingerprint"],
             json.dumps(list(b["ext_domains"])), b["captured_at"]))

    def add_alert(self, site_id, url, severity, category, message, detail=""):
        self.q(
            "INSERT INTO alerts(site_id,url,severity,category,message,detail,ts) "
            "VALUES(?,?,?,?,?,?,?)",
            (site_id, url, severity, category, message, detail,
             datetime.now().isoformat(timespec="seconds")))
        return self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def get_alerts(self, limit=500, unack_only=False):
        clause = " AND acknowledged=0" if unack_only else ""
        return self.fetch(
            f"SELECT a.id,a.severity,a.category,a.message,a.ts,"
            f"s.label,a.url,a.acknowledged,a.detail "
            f"FROM alerts a JOIN sites s ON a.site_id=s.id "
            f"WHERE 1=1{clause} ORDER BY a.ts DESC LIMIT ?", (limit,))

    def ack_alert(self, alert_id):
        self.q("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    def ack_all(self):
        self.q("UPDATE alerts SET acknowledged=1")

    def update_site_status(self, site_id, status, risk, last_check):
        self.q(
            "UPDATE sites SET status=?,risk=?,last_check=? WHERE id=?",
            (status, risk, last_check, site_id))

    def log_check(self, site_id, code, chash, clen, ms, nalerts):
        self.q(
            "INSERT INTO checks(site_id,ts,status_code,content_hash,"
            "content_len,resp_ms,alert_count) VALUES(?,?,?,?,?,?,?)",
            (site_id, datetime.now().isoformat(timespec="seconds"),
             code, chash, clen, ms, nalerts))

    def get_history(self, site_id, limit=50):
        return self.fetch(
            "SELECT ts,status_code,resp_ms,alert_count FROM checks "
            "WHERE site_id=? ORDER BY ts DESC LIMIT ?", (site_id, limit))

    def clear_baseline(self, site_id):
        self.q("DELETE FROM baselines WHERE site_id=?", (site_id,))


# ════════════════════════════════════════════════════════
#  FETCH ENGINE
# ════════════════════════════════════════════════════════
@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status_code: int = 0
    content: str = ""
    content_len: int = 0
    content_hash: str = ""
    title: str = ""
    resp_ms: int = 0
    ssl_expiry: str = ""
    ssl_fingerprint: str = ""
    ext_domains: set = field(default_factory=set)
    error: str = ""


def _extract_title(body: str) -> str:
    m = re.search(r'<title[^>]*>([^<]{0,200})</title>', body, re.I | re.S)
    return m.group(1).strip() if m else ""


def _extract_ext_domains(body: str, host: str) -> set:
    srcs = re.findall(
        r'(?:src|href|action)\s*=\s*["\']?(https?://[^"\'>\s]+)', body, re.I)
    domains = set()
    for src in srcs:
        try:
            parsed = urllib.parse.urlparse(src)
            d = parsed.netloc.lower()
            if d and d != host.lower():
                domains.add(d)
        except Exception:
            pass
    return domains


def _ssl_info(hostname: str) -> tuple[str, str]:
    """Returns (expiry_iso, fingerprint_sha256)."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=8),
                server_hostname=hostname) as s:
            cert = s.getpeercert(binary_form=False)
            der  = s.getpeercert(binary_form=True)
        not_after = cert.get("notAfter", "")
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").isoformat()
        fp = hashlib.sha256(der).hexdigest()
        return expiry, fp
    except Exception:
        return "", ""


def fetch_site(url: str, timeout: int = 15) -> FetchResult:
    res = FetchResult(url=url)
    t0 = time.perf_counter()
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/124.0 Safari/537.36"),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handler = urllib.request.HTTPSHandler(context=ctx)
        opener  = urllib.request.build_opener(handler)

        with opener.open(req, timeout=timeout) as resp:
            res.final_url   = resp.geturl()
            res.status_code = resp.getcode()
            raw             = resp.read()

        res.resp_ms     = int((time.perf_counter() - t0) * 1000)
        res.content_len = len(raw)

        # Decode
        try:
            res.content = raw.decode("utf-8", errors="replace")
        except Exception:
            res.content = raw.decode("latin-1", errors="replace")

        res.content_hash = hashlib.sha256(raw).hexdigest()
        res.title        = _extract_title(res.content)
        res.ext_domains  = _extract_ext_domains(res.content, hostname)

        # SSL info (only for https, non-blocking)
        if parsed.scheme == "https":
            res.ssl_expiry, res.ssl_fingerprint = _ssl_info(hostname)

    except urllib.error.HTTPError as e:
        res.status_code = e.code
        res.error       = f"HTTP {e.code}: {e.reason}"
        res.resp_ms     = int((time.perf_counter() - t0) * 1000)
    except Exception as e:
        res.error   = str(e)
        res.resp_ms = int((time.perf_counter() - t0) * 1000)

    return res


# ════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ════════════════════════════════════════════════════════
@dataclass
class Finding:
    severity: str
    category: str
    message: str
    detail: str = ""


def analyse(result: FetchResult, baseline: Optional[tuple]) -> list[Finding]:
    findings: list[Finding] = []
    body_lower = result.content.lower()

    # ── Pattern scanning ─────────────────────────────
    for pattern, sev, msg in ALL_PATTERNS:
        if re.search(pattern, result.content, re.I | re.S):
            category = (
                "DEFACEMENT"  if "Defacement" in msg else
                "MALWARE"     if "Malware"    in msg else
                "PHISHING"    if "Phishing"   in msg else
                "SUSPICIOUS"
            )
            findings.append(Finding(sev, category, msg,
                                    f"Pattern: {pattern[:60]}"))

    if not baseline:
        return findings   # first run — no comparison possible

    (b_hash, b_title, b_code, b_len, b_redirect,
     b_ssl_exp, b_ssl_fp, b_ext_json, b_time) = baseline

    b_ext: set = set(json.loads(b_ext_json)) if b_ext_json else set()

    # ── HTTP status change ────────────────────────────
    if result.status_code and b_code and result.status_code != b_code:
        sev = "HIGH" if result.status_code >= 500 else "MEDIUM"
        findings.append(Finding(sev, "STATUS_CHANGE",
            f"HTTP status changed: {b_code} → {result.status_code}"))

    # ── Content hash ──────────────────────────────────
    if result.content_hash and b_hash and result.content_hash != b_hash:
        findings.append(Finding("MEDIUM", "CONTENT_CHANGED",
            "Page content changed since baseline was set",
            f"Old hash: {b_hash[:16]}…  New: {result.content_hash[:16]}…"))

    # ── Title change ──────────────────────────────────
    if b_title and result.title and result.title != b_title:
        findings.append(Finding("HIGH", "TITLE_CHANGED",
            f"Page title changed: '{b_title}' → '{result.title}'"))

    # ── Content-length deviation (> 20%) ─────────────
    if b_len and result.content_len:
        ratio = abs(result.content_len - b_len) / max(b_len, 1)
        if ratio > 0.20:
            sev = "HIGH" if ratio > 0.50 else "MEDIUM"
            findings.append(Finding(sev, "SIZE_CHANGE",
                f"Content size changed {b_len} → {result.content_len} bytes "
                f"({ratio*100:.0f}% deviation)"))

    # ── Redirect change ───────────────────────────────
    if b_redirect and result.final_url and result.final_url != b_redirect:
        findings.append(Finding("HIGH", "REDIRECT_CHANGE",
            f"Redirect destination changed",
            f"Was: {b_redirect}\nNow: {result.final_url}"))

    # ── SSL expiry ────────────────────────────────────
    if result.ssl_expiry:
        try:
            exp = datetime.fromisoformat(result.ssl_expiry)
            days_left = (exp - datetime.now()).days
            if days_left < 0:
                findings.append(Finding("CRITICAL", "SSL",
                    "SSL certificate has EXPIRED"))
            elif days_left < 7:
                findings.append(Finding("HIGH", "SSL",
                    f"SSL certificate expires in {days_left} day(s)"))
            elif days_left < 30:
                findings.append(Finding("MEDIUM", "SSL",
                    f"SSL certificate expires in {days_left} days"))
        except Exception:
            pass

    # ── SSL fingerprint change ─────────────────────────
    if b_ssl_fp and result.ssl_fingerprint and result.ssl_fingerprint != b_ssl_fp:
        findings.append(Finding("CRITICAL", "SSL",
            "SSL certificate fingerprint changed — possible MITM or cert reissue",
            f"Old FP: {b_ssl_fp[:20]}…"))

    # ── New external domains ──────────────────────────
    new_domains = result.ext_domains - b_ext
    if new_domains:
        findings.append(Finding("MEDIUM", "NEW_EXTERNAL_DOMAIN",
            f"New external domain(s) added to page: {', '.join(sorted(new_domains))}"))

    # ── Response time spike (> 8 s) ───────────────────
    if result.resp_ms > 8000:
        findings.append(Finding("LOW", "SLOW_RESPONSE",
            f"Response time spike: {result.resp_ms} ms — possible DDoS or overload"))

    return findings


def highest_severity(findings: list[Finding]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK"]
    sevs = [f.severity for f in findings]
    for s in order:
        if s in sevs:
            return s
    return "OK"


# ════════════════════════════════════════════════════════
#  EMAIL ALERTS
# ════════════════════════════════════════════════════════
def send_email_alert(db: Database, site_label: str, url: str,
                     findings: list[Finding]):
    smtp_host = db.get_setting("smtp_host")
    smtp_port = db.get_setting("smtp_port", "587")
    smtp_user = db.get_setting("smtp_user")
    smtp_pass = db.get_setting("smtp_pass")
    smtp_to   = db.get_setting("smtp_to")

    if not all([smtp_host, smtp_user, smtp_pass, smtp_to]):
        return  # email not configured

    try:
        subject = (
            f"[WATCHDOG] {'🚨' if any(f.severity=='CRITICAL' for f in findings) else '⚠️'} "
            f"Alert for {site_label}")

        rows = "\n".join(
            f"  [{f.severity}] {f.category}: {f.message}"
            for f in findings)
        body = (
            f"Website Watchdog Alert\n{'='*50}\n"
            f"Site:  {site_label}\n"
            f"URL:   {url}\n"
            f"Time:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"Findings:\n{rows}\n\n"
            f"Log in to the Watchdog dashboard to review and acknowledge.\n")

        msg = MIMEText(body, "plain")
        msg["Subject"] = subject
        msg["From"]    = smtp_user
        msg["To"]      = smtp_to

        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as s:
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.send_message(msg)
    except Exception:
        pass  # don't crash monitor thread on email failure


# ════════════════════════════════════════════════════════
#  MONITOR ENGINE
# ════════════════════════════════════════════════════════
class MonitorEngine:
    def __init__(self, db: Database, on_alert, on_check):
        self.db       = db
        self.on_alert = on_alert   # callback(site_id, url, findings)
        self.on_check = on_check   # callback(site_id)
        self._threads: dict[int, threading.Thread] = {}
        self._stop_events: dict[int, threading.Event] = {}
        self._running = True

    def start_site(self, site_id: int, url: str, interval: int):
        self.stop_site(site_id)
        ev = threading.Event()
        self._stop_events[site_id] = ev
        t = threading.Thread(
            target=self._loop, args=(site_id, url, interval, ev),
            daemon=True, name=f"monitor-{site_id}")
        self._threads[site_id] = t
        t.start()

    def stop_site(self, site_id: int):
        if site_id in self._stop_events:
            self._stop_events[site_id].set()
        self._threads.pop(site_id, None)
        self._stop_events.pop(site_id, None)

    def stop_all(self):
        for ev in self._stop_events.values():
            ev.set()

    def _loop(self, site_id: int, url: str, interval: int, stop: threading.Event):
        """Run once immediately, then wait `interval` seconds, repeat."""
        while not stop.is_set():
            self._run_check(site_id, url)
            stop.wait(interval)

    def _run_check(self, site_id: int, url: str):
        result   = fetch_site(url)
        baseline = self.db.get_baseline(site_id)

        if result.error and not result.status_code:
            # Network-level failure — alert + mark unreachable
            findings = [Finding("HIGH", "UNREACHABLE",
                                f"Site unreachable: {result.error}")]
        else:
            findings = analyse(result, baseline)

        # Save/refresh baseline on first run
        if not baseline and not result.error:
            self.db.save_baseline(site_id, {
                "content_hash":    result.content_hash,
                "title":           result.title,
                "status_code":     result.status_code,
                "content_len":     result.content_len,
                "redirect_url":    result.final_url,
                "ssl_expiry":      result.ssl_expiry,
                "ssl_fingerprint": result.ssl_fingerprint,
                "ext_domains":     result.ext_domains,
                "captured_at":     datetime.now().isoformat(timespec="seconds"),
            })

        sev   = highest_severity(findings) if findings else "OK"
        risk  = sev if findings else "OK"
        status = "ALERT" if findings else "OK"

        self.db.update_site_status(
            site_id, status, risk,
            datetime.now().isoformat(timespec="seconds"))
        self.db.log_check(
            site_id, result.status_code, result.content_hash,
            result.content_len, result.resp_ms, len(findings))

        for f in findings:
            self.db.add_alert(site_id, url, f.severity, f.category,
                              f.message, f.detail)

        if findings:
            send_email_alert(self.db, url, url, findings)
            self.on_alert(site_id, url, findings)

        self.on_check(site_id)


# ════════════════════════════════════════════════════════
#  HTML REPORT
# ════════════════════════════════════════════════════════
def generate_report(db: Database) -> str:
    sites  = db.get_sites()
    alerts = db.get_alerts(limit=1000)
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total   = len(sites)
    ok      = sum(1 for s in sites if s[5] == "OK")
    alerted = sum(1 for s in sites if s[5] == "ALERT")
    pending = sum(1 for s in sites if s[5] == "PENDING")
    crit    = sum(1 for a in alerts if a[1] == "CRITICAL")

    def esc(s): return html.escape(str(s or ""))
    def sc(sev): return {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW,
                          "LOW": CYAN, "OK": GREEN}.get(sev, TEXT_SEC)

    site_rows = ""
    for s in sites:
        sid, url, label, interval, enabled, status, risk, last_check = s
        rc = sc(risk)
        site_rows += f"""
<tr>
  <td>{esc(label)}</td>
  <td class="mono small">{esc(url)}</td>
  <td><span class="badge" style="background:{sc(status)};color:#000">{esc(status)}</span></td>
  <td><span style="color:{rc}">{esc(risk)}</span></td>
  <td class="center">{interval}s</td>
  <td class="small">{esc(last_check or '—')}</td>
</tr>"""

    alert_rows = ""
    for a in alerts[:200]:
        aid, sev, cat, msg, ts, label, url, ack, detail = a
        rc = sc(sev)
        ack_lbl = "✓" if ack else ""
        alert_rows += f"""
<tr>
  <td><span class="badge" style="background:{rc};color:#000">{esc(sev)}</span></td>
  <td style="color:#94A3B8;font-size:11px">{esc(cat)}</td>
  <td>{esc(label)}</td>
  <td class="mono small">{esc(url)}</td>
  <td>{esc(msg)}</td>
  <td class="small">{esc(ts)}</td>
  <td class="center" style="color:{GREEN}">{ack_lbl}</td>
</tr>"""

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>Website Watchdog Report — {esc(now)}</title>
<style>
  :root{{--bg:#07080D;--card:#0F1320;--border:#1A2035;
         --text:#E2E8F0;--muted:#475569;--accent:#3B82F6}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);
        font-family:'Segoe UI',Arial,sans-serif;font-size:14px;padding:32px}}
  h1{{font-size:24px;color:var(--accent);margin-bottom:4px}}
  h2{{font-size:16px;color:var(--accent);margin:28px 0 12px;
      padding-bottom:6px;border-bottom:1px solid var(--border)}}
  .meta{{color:var(--muted);font-size:12px;margin-bottom:24px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
         gap:12px;margin-bottom:28px}}
  .stat{{background:var(--card);border:1px solid var(--border);
         border-radius:8px;padding:14px;text-align:center}}
  .stat .num{{font-size:28px;font-weight:700}}
  .stat .lbl{{color:var(--muted);font-size:11px;text-transform:uppercase;
              letter-spacing:.06em;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;background:var(--card);
         border:1px solid var(--border);border-radius:8px;overflow:hidden}}
  th{{background:#0B0E16;color:var(--muted);font-size:11px;
      text-transform:uppercase;letter-spacing:.05em;padding:10px 12px;text-align:left}}
  td{{padding:9px 12px;border-top:1px solid var(--border);vertical-align:top}}
  tr:hover td{{background:#0D1220}}
  .mono{{font-family:Consolas,monospace}}
  .small{{font-size:11px}}
  .center{{text-align:center}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;
          font-size:11px;font-weight:700}}
  footer{{margin-top:40px;color:var(--muted);font-size:11px;
          border-top:1px solid var(--border);padding-top:14px}}
</style></head><body>
<h1>🛡 Website Watchdog Report</h1>
<div class="meta">Generated: {esc(now)}</div>
<div class="grid">
  <div class="stat"><div class="num">{total}</div><div class="lbl">Sites Monitored</div></div>
  <div class="stat"><div class="num" style="color:{GREEN}">{ok}</div><div class="lbl">OK</div></div>
  <div class="stat"><div class="num" style="color:{ORANGE}">{alerted}</div><div class="lbl">Alerting</div></div>
  <div class="stat"><div class="num" style="color:{TEXT_SEC}">{pending}</div><div class="lbl">Pending</div></div>
  <div class="stat"><div class="num" style="color:{RED}">{crit}</div><div class="lbl">Critical Alerts</div></div>
  <div class="stat"><div class="num">{len(alerts)}</div><div class="lbl">Total Alerts</div></div>
</div>
<h2>Monitored Sites</h2>
<table><thead><tr>
  <th>Label</th><th>URL</th><th>Status</th>
  <th>Risk</th><th>Interval</th><th>Last Check</th>
</tr></thead><tbody>{site_rows}</tbody></table>
<h2>Alert Log (latest 200)</h2>
<table><thead><tr>
  <th>Severity</th><th>Category</th><th>Site</th>
  <th>URL</th><th>Message</th><th>Timestamp</th><th>Ack</th>
</tr></thead><tbody>{alert_rows}</tbody></table>
<footer>Website Watchdog — passive monitoring only. No scanning or attack traffic generated.</footer>
</body></html>"""


# ════════════════════════════════════════════════════════
#  GUI
# ════════════════════════════════════════════════════════
class WatchdogApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Website Watchdog")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(1100, 680)

        w, h = 1280, 820
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

        self.db = Database()
        self.engine = MonitorEngine(
            self.db,
            on_alert=self._on_alert_callback,
            on_check=self._on_check_callback,
        )
        self._alert_count = 0
        self._site_rows: dict[int, str] = {}   # site_id → tree item iid

        self._build_ui()
        self._load_sites()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ────────────────────────────────────────────────────
    #  BUILD UI
    # ────────────────────────────────────────────────────
    def _build_ui(self):
        # ── top toolbar ──────────────────────────────
        toolbar = tk.Frame(self, bg=BG_PANEL, pady=10)
        toolbar.pack(fill="x")

        tk.Label(toolbar, text=" 🛡  Website Watchdog",
                 bg=BG_PANEL, fg=ACCENT,
                 font=("Segoe UI", 15, "bold")).pack(side="left", padx=14)

        btn = dict(relief="flat", cursor="hand2",
                   font=("Segoe UI", 9, "bold"), padx=14, pady=6)

        tk.Button(toolbar, text="＋  Add Site",
                  bg=ACCENT, fg="#fff",
                  activebackground="#2563EB",
                  command=self._dlg_add_site, **btn).pack(side="left", padx=4)

        tk.Button(toolbar, text="🗑  Remove",
                  bg=BG_CARD, fg=RED,
                  activebackground=BG_ROW,
                  command=self._remove_site, **btn).pack(side="left", padx=2)

        tk.Button(toolbar, text="↺  Reset Baseline",
                  bg=BG_CARD, fg=YELLOW,
                  activebackground=BG_ROW,
                  command=self._reset_baseline, **btn).pack(side="left", padx=2)

        tk.Button(toolbar, text="✓  Ack All Alerts",
                  bg=BG_CARD, fg=GREEN,
                  activebackground=BG_ROW,
                  command=self._ack_all, **btn).pack(side="left", padx=2)

        tk.Button(toolbar, text="📄  Export Report",
                  bg=BG_CARD, fg=PURPLE,
                  activebackground=BG_ROW,
                  command=self._export_report, **btn).pack(side="left", padx=2)

        tk.Button(toolbar, text="⚙  Settings",
                  bg=BG_CARD, fg=TEXT_SEC,
                  activebackground=BG_ROW,
                  command=self._dlg_settings, **btn).pack(side="left", padx=2)

        self._alert_badge = tk.Label(
            toolbar, text="",
            bg=RED, fg="#fff",
            font=("Segoe UI", 9, "bold"), padx=8, pady=3)
        # only pack when there are alerts

        self._status_var = tk.StringVar(value="Starting…")
        tk.Label(toolbar, textvariable=self._status_var,
                 bg=BG_PANEL, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(side="right", padx=16)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── summary stats bar ────────────────────────
        stats_bar = tk.Frame(self, bg=BG_PANEL, pady=8)
        stats_bar.pack(fill="x", padx=16)

        self._sv: dict[str, tk.StringVar] = {}
        stat_defs = [
            ("total",   "Sites",        TEXT_PRI),
            ("ok",      "OK",           GREEN),
            ("alert",   "Alerting",     ORANGE),
            ("pending", "Pending",      CYAN),
            ("crit",    "🚨 Critical",  RED),
            ("unack",   "Unacked",      YELLOW),
        ]
        for key, lbl, color in stat_defs:
            f = tk.Frame(stats_bar, bg=BG_CARD,
                         highlightthickness=1, highlightbackground=BORDER,
                         padx=14, pady=6)
            f.pack(side="left", padx=4)
            v = tk.StringVar(value="0")
            self._sv[key] = v
            tk.Label(f, textvariable=v, bg=BG_CARD, fg=color,
                     font=("Consolas", 17, "bold")).pack()
            tk.Label(f, text=lbl, bg=BG_CARD, fg=TEXT_SEC,
                     font=("Segoe UI", 8)).pack()

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── notebook ─────────────────────────────────
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",       background=BG,      borderwidth=0)
        style.configure("TNotebook.Tab",   background=BG_CARD, foreground=TEXT_SEC,
                        padding=[18, 7], font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", BG_PANEL)],
                  foreground=[("selected", ACCENT)])
        for tree_style in ("Treeview", "Alert.Treeview"):
            style.configure(tree_style,
                            background=BG_ROW, fieldbackground=BG_ROW,
                            foreground=TEXT_PRI, rowheight=28,
                            font=MONO)
            style.configure(f"{tree_style}.Heading",
                            background=BG_CARD, foreground=TEXT_SEC,
                            relief="flat", font=("Segoe UI", 9, "bold"))
            style.map(tree_style,
                      background=[("selected", BG_CARD)],
                      foreground=[("selected", ACCENT)])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        tab_sites   = tk.Frame(nb, bg=BG)
        tab_alerts  = tk.Frame(nb, bg=BG)
        tab_history = tk.Frame(nb, bg=BG)
        nb.add(tab_sites,   text="  Sites  ")
        nb.add(tab_alerts,  text="  Alerts  ")
        nb.add(tab_history, text="  History  ")
        nb.bind("<<NotebookTabChanged>>",
                lambda _: self._refresh_alerts())

        self._build_sites_tab(tab_sites)
        self._build_alerts_tab(tab_alerts)
        self._build_history_tab(tab_history)

    # ── Sites tab ────────────────────────────────────
    def _build_sites_tab(self, parent):
        cols = ("status","risk","label","url","interval","last_check","baseline")
        hdrs = ("Status","Risk","Label","URL","Interval","Last Check","Baseline")
        widths=(70, 70, 160, 300, 70, 145, 80)

        frame = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        frame.pack(fill="both", expand=True, padx=10, pady=8)

        self._site_tree = ttk.Treeview(frame, columns=cols,
                                        show="headings", selectmode="browse")
        for col, hdr, w in zip(cols, hdrs, widths):
            self._site_tree.heading(col, text=hdr)
            self._site_tree.column(col, width=w, minwidth=40, anchor="center")
        self._site_tree.column("label", anchor="w")
        self._site_tree.column("url",   anchor="w")

        vsb = tk.Scrollbar(frame, orient="vertical",
                           command=self._site_tree.yview)
        self._site_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._site_tree.pack(fill="both", expand=True)

        for tag, color in [
            ("ALERT", RED), ("OK", GREEN), ("PENDING", CYAN), ("ERROR", ORANGE)
        ]:
            self._site_tree.tag_configure(tag, foreground=color)

        # detail panel
        dp = tk.Frame(parent, bg=BG_CARD, pady=10, padx=14, height=90)
        dp.pack(fill="x", padx=10, pady=(0, 6))
        dp.pack_propagate(False)
        self._site_detail = tk.StringVar(
            value="Select a site to view details.")
        tk.Label(dp, textvariable=self._site_detail,
                 bg=BG_CARD, fg=TEXT_PRI,
                 font=("Segoe UI", 9), justify="left",
                 wraplength=1200, anchor="nw").pack(fill="both", expand=True)

        self._site_tree.bind("<<TreeviewSelect>>", self._on_site_select)

    # ── Alerts tab ───────────────────────────────────
    def _build_alerts_tab(self, parent):
        sf = tk.Frame(parent, bg=BG_PANEL, pady=8, padx=12)
        sf.pack(fill="x")

        tk.Label(sf, text="Filter:", bg=BG_PANEL, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(side="left")
        self._alert_filter = tk.StringVar()
        self._alert_filter.trace_add("write", lambda *_: self._refresh_alerts())
        tk.Entry(sf, textvariable=self._alert_filter,
                 bg=BG_INPUT, fg=TEXT_PRI, insertbackground=ACCENT,
                 relief="flat", font=("Segoe UI", 10), width=26
                 ).pack(side="left", padx=8)

        self._unack_only = tk.BooleanVar(value=False)
        tk.Checkbutton(sf, text="Unacknowledged only",
                       variable=self._unack_only,
                       bg=BG_PANEL, fg=TEXT_SEC, selectcolor=BG_CARD,
                       activebackground=BG_PANEL,
                       command=self._refresh_alerts).pack(side="left", padx=8)

        tk.Button(sf, text="✓ Ack Selected", bg=BG_CARD, fg=GREEN,
                  relief="flat", cursor="hand2",
                  font=("Segoe UI", 9), padx=10, pady=4,
                  command=self._ack_selected).pack(side="right")

        cols = ("sev","cat","site","url","message","ts","ack")
        hdrs = ("Severity","Category","Site","URL","Message","Timestamp","Ack")
        widths=(80, 120, 150, 220, 400, 130, 35)

        frame = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        frame.pack(fill="both", expand=True, padx=10, pady=(0,8))

        self._alert_tree = ttk.Treeview(frame, columns=cols,
                                         show="headings", selectmode="extended",
                                         style="Alert.Treeview")
        for col, hdr, w in zip(cols, hdrs, widths):
            self._alert_tree.heading(col, text=hdr)
            self._alert_tree.column(col, width=w, minwidth=30, anchor="center")
        self._alert_tree.column("message", anchor="w")
        self._alert_tree.column("site",    anchor="w")

        vsb2 = tk.Scrollbar(frame, orient="vertical",
                            command=self._alert_tree.yview)
        self._alert_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side="right", fill="y")
        self._alert_tree.pack(fill="both", expand=True)

        for tag, color in [
            ("CRITICAL",RED),("HIGH",ORANGE),("MEDIUM",YELLOW),
            ("LOW",CYAN),("INFO",TEXT_SEC),("ACK",TEXT_MUT),
        ]:
            self._alert_tree.tag_configure(tag, foreground=color)

    # ── History tab ──────────────────────────────────
    def _build_history_tab(self, parent):
        top = tk.Frame(parent, bg=BG_PANEL, pady=8, padx=12)
        top.pack(fill="x")

        tk.Label(top, text="Site:", bg=BG_PANEL, fg=TEXT_SEC,
                 font=("Segoe UI", 9)).pack(side="left")
        self._hist_site_var = tk.StringVar()
        self._hist_combo = ttk.Combobox(top, textvariable=self._hist_site_var,
                                         width=50, state="readonly")
        self._hist_combo.pack(side="left", padx=8)
        self._hist_combo.bind("<<ComboboxSelected>>", self._load_history)

        cols = ("ts","code","resp_ms","alerts")
        hdrs = ("Timestamp","HTTP Code","Response ms","Alerts")

        frame = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        frame.pack(fill="both", expand=True, padx=10, pady=(4,8))

        self._hist_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, hdr in zip(cols, hdrs):
            self._hist_tree.heading(col, text=hdr)
            self._hist_tree.column(col, width=200, anchor="center")

        vsb3 = tk.Scrollbar(frame, orient="vertical",
                            command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=vsb3.set)
        vsb3.pack(side="right", fill="y")
        self._hist_tree.pack(fill="both", expand=True)

        self._hist_tree.tag_configure("alert", foreground=ORANGE)
        self._hist_tree.tag_configure("ok",    foreground=GREEN)

    # ────────────────────────────────────────────────────
    #  DATA LOADING
    # ────────────────────────────────────────────────────
    def _load_sites(self):
        """Load persisted sites from DB and start monitor threads."""
        rows = self.db.get_sites()
        self._site_tree.delete(*self._site_tree.get_children())
        self._site_rows.clear()

        for s in rows:
            sid, url, label, interval, enabled, status, risk, last_check = s
            if enabled:
                self.engine.start_site(sid, url, interval)
            iid = self._insert_site_row(sid, label, url, interval,
                                         status, risk, last_check)
            self._site_rows[sid] = iid

        self._refresh_stats()
        self._refresh_alerts()
        self._update_hist_combo()
        self._status_var.set(
            f"Monitoring {len(rows)} site(s)  —  {datetime.now().strftime('%H:%M:%S')}")

    def _insert_site_row(self, sid, label, url, interval,
                          status, risk, last_check) -> str:
        has_bl = self.db.get_baseline(sid) is not None
        tag = {"ALERT": "ALERT", "OK": "OK", "PENDING": "PENDING"}.get(status, "PENDING")
        iid = self._site_tree.insert("", "end", iid=str(sid), tags=(tag,),
            values=(
                status, risk, label, url,
                f"{interval}s", last_check or "—",
                "Yes" if has_bl else "No",
            ))
        return iid

    def _refresh_site_row(self, site_id: int):
        row = self.db.fetchone(
            "SELECT url,label,interval_sec,enabled,status,risk,last_check "
            "FROM sites WHERE id=?", (site_id,))
        if not row:
            return
        url, label, interval, enabled, status, risk, last_check = row
        has_bl = self.db.get_baseline(site_id) is not None
        tag = {"ALERT": "ALERT", "OK": "OK", "PENDING": "PENDING"}.get(status, "PENDING")
        iid = str(site_id)
        if self._site_tree.exists(iid):
            self._site_tree.item(iid, tags=(tag,), values=(
                status, risk, label, url,
                f"{interval}s", last_check or "—",
                "Yes" if has_bl else "No",
            ))

    def _refresh_alerts(self):
        q   = self._alert_filter.get().lower()
        uo  = self._unack_only.get()
        rows = self.db.get_alerts(unack_only=uo)

        self._alert_tree.delete(*self._alert_tree.get_children())
        for a in rows:
            aid, sev, cat, msg, ts, label, url, ack, detail = a
            if q and q not in (sev+cat+msg+label+url).lower():
                continue
            tag = "ACK" if ack else sev
            ack_sym = "✓" if ack else ""
            self._alert_tree.insert("", "end", iid=str(aid), tags=(tag,),
                values=(sev, cat, label, url, msg, ts, ack_sym))

        self._refresh_stats()

    def _refresh_stats(self):
        sites  = self.db.get_sites()
        alerts = self.db.get_alerts(unack_only=True)
        self._sv["total"].set(str(len(sites)))
        self._sv["ok"].set(str(sum(1 for s in sites if s[5]=="OK")))
        self._sv["alert"].set(str(sum(1 for s in sites if s[5]=="ALERT")))
        self._sv["pending"].set(str(sum(1 for s in sites if s[5]=="PENDING")))
        crit = sum(1 for a in alerts if a[1]=="CRITICAL")
        self._sv["crit"].set(str(crit))
        self._sv["unack"].set(str(len(alerts)))

        # alert badge on toolbar
        if len(alerts) > 0:
            self._alert_badge.config(text=f" 🔔 {len(alerts)} unacked ")
            self._alert_badge.pack(side="right", padx=8)
        else:
            self._alert_badge.pack_forget()

    def _update_hist_combo(self):
        sites = self.db.get_sites()
        self._hist_combo["values"] = [
            f"{s[0]}  {s[2]} ({s[1]})" for s in sites]

    def _load_history(self, _=None):
        val = self._hist_site_var.get()
        if not val:
            return
        site_id = int(val.split()[0])
        rows = self.db.get_history(site_id)
        self._hist_tree.delete(*self._hist_tree.get_children())
        for r in rows:
            ts, code, ms, nalerts = r
            tag = "alert" if nalerts else "ok"
            self._hist_tree.insert("", "end", tags=(tag,),
                values=(ts, code or "—", f"{ms} ms", nalerts or "0"))

    # ────────────────────────────────────────────────────
    #  CALLBACKS FROM MONITOR THREAD
    # ────────────────────────────────────────────────────
    def _on_alert_callback(self, site_id: int, url: str, findings: list):
        self.after(0, lambda: self._handle_alert_ui(site_id, findings))

    def _on_check_callback(self, site_id: int):
        self.after(0, lambda: self._refresh_site_row(site_id))
        self.after(0, self._refresh_alerts)

    def _handle_alert_ui(self, site_id: int, findings: list):
        self._refresh_site_row(site_id)
        self._refresh_alerts()
        # bell
        try:
            self.bell()
        except Exception:
            pass
        # flash title
        worst = highest_severity(findings)
        color = SEV_COLOR.get(worst, YELLOW)
        orig_title = self.title()
        self.title(f"🚨 ALERT [{worst}]  —  Website Watchdog")
        self.after(3000, lambda: self.title(orig_title))

    # ────────────────────────────────────────────────────
    #  ACTIONS
    # ────────────────────────────────────────────────────
    def _dlg_add_site(self):
        dlg = tk.Toplevel(self)
        dlg.title("Add Website to Monitor")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.geometry("460x260")
        dlg.grab_set()

        fields = {}
        defs = [
            ("URL",      "https://example.com"),
            ("Label",    "My Website"),
            ("Interval (seconds)", "300"),
        ]
        for i, (lbl, placeholder) in enumerate(defs):
            tk.Label(dlg, text=lbl, bg=BG, fg=TEXT_SEC,
                     font=("Segoe UI", 9)).grid(
                row=i, column=0, sticky="w", padx=20, pady=8)
            v = tk.StringVar(value=placeholder)
            e = tk.Entry(dlg, textvariable=v, bg=BG_INPUT, fg=TEXT_PRI,
                         insertbackground=ACCENT, relief="flat",
                         font=("Consolas", 10), width=34)
            e.grid(row=i, column=1, padx=10, pady=8, sticky="ew")
            e.bind("<FocusIn>",
                   lambda ev, vv=v, pp=placeholder:
                   vv.set("") if vv.get() == pp else None)
            fields[lbl] = v

        def do_add():
            url      = fields["URL"].get().strip()
            label    = fields["Label"].get().strip()
            interval = fields["Interval (seconds)"].get().strip()
            if not url.startswith(("http://", "https://")):
                messagebox.showerror("Invalid URL",
                    "URL must start with http:// or https://", parent=dlg)
                return
            try:
                iv = int(interval)
                assert 10 <= iv <= 86400
            except Exception:
                messagebox.showerror("Invalid interval",
                    "Interval must be 10–86400 seconds.", parent=dlg)
                return
            ok = self.db.add_site(url, label, iv)
            if not ok:
                messagebox.showerror("Duplicate", "URL already monitored.",
                                     parent=dlg)
                return
            row = self.db.fetchone(
                "SELECT id FROM sites WHERE url=?", (url,))
            sid = row[0]
            self._insert_site_row(sid, label or url, url, iv,
                                   "PENDING", "INFO", None)
            self.engine.start_site(sid, url, iv)
            self._update_hist_combo()
            self._refresh_stats()
            self._status_var.set(f"Added: {url}")
            dlg.destroy()

        tk.Button(dlg, text="Add Site", bg=ACCENT, fg="#fff",
                  relief="flat", font=("Segoe UI", 10, "bold"),
                  padx=20, pady=8, cursor="hand2",
                  command=do_add).grid(row=3, column=0, columnspan=2, pady=14)

    def _get_selected_site_id(self) -> Optional[int]:
        sel = self._site_tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected", "Select a site first.")
            return None
        return int(sel[0])

    def _remove_site(self):
        sid = self._get_selected_site_id()
        if sid is None:
            return
        if not messagebox.askyesno("Remove site",
                "Remove this site and all its history?"):
            return
        self.engine.stop_site(sid)
        self.db.remove_site(sid)
        if self._site_tree.exists(str(sid)):
            self._site_tree.delete(str(sid))
        self._refresh_stats()
        self._update_hist_combo()

    def _reset_baseline(self):
        sid = self._get_selected_site_id()
        if sid is None:
            return
        self.db.clear_baseline(sid)
        self._refresh_site_row(sid)
        self._status_var.set("Baseline cleared — next check will re-capture it.")

    def _ack_all(self):
        self.db.ack_all()
        self._refresh_alerts()

    def _ack_selected(self):
        for iid in self._alert_tree.selection():
            self.db.ack_alert(int(iid))
        self._refresh_alerts()

    def _on_site_select(self, _=None):
        sid = self._get_selected_site_id()
        if sid is None:
            return
        row = self.db.fetchone(
            "SELECT url,label,interval_sec,status,risk,last_check "
            "FROM sites WHERE id=?", (sid,))
        if not row:
            return
        url, label, interval, status, risk, last_check = row
        bl = self.db.get_baseline(sid)
        bl_time = bl[8] if bl else "Not captured yet"
        bl_hash = bl[0][:16] + "…" if bl else "—"
        hist = self.db.get_history(sid, limit=1)
        last_resp = f"{hist[0][2]} ms" if hist else "—"
        alerts = self.db.fetch(
            "SELECT COUNT(*) FROM alerts WHERE site_id=? AND acknowledged=0",
            (sid,))[0][0]

        self._site_detail.set(
            f"URL: {url}   |   Label: {label}   |   Interval: {interval}s   |   "
            f"Status: {status}   |   Risk: {risk}   |   Last check: {last_check or '—'}   |   "
            f"Baseline: {bl_time}  hash: {bl_hash}   |   "
            f"Last resp: {last_resp}   |   Unacked alerts: {alerts}")

    def _export_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html"), ("All files", "*.*")],
            initialfile=f"watchdog_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        )
        if not path:
            return
        rep = generate_report(self.db)
        with open(path, "w", encoding="utf-8") as f:
            f.write(rep)
        self._status_var.set(f"✓ Report saved → {path}")
        if messagebox.askyesno("Open?", f"Saved:\n{path}\n\nOpen in browser?"):
            webbrowser.open(f"file:///{path.replace(os.sep, '/')}")

    def _dlg_settings(self):
        dlg = tk.Toplevel(self)
        dlg.title("Settings — Email Alerts")
        dlg.configure(bg=BG)
        dlg.resizable(False, False)
        dlg.geometry("480x360")
        dlg.grab_set()

        tk.Label(dlg, text="SMTP Email Alert Configuration",
                 bg=BG, fg=ACCENT,
                 font=("Segoe UI", 11, "bold")).grid(
            row=0, column=0, columnspan=2, padx=20, pady=(16, 10), sticky="w")
        tk.Label(dlg, text="Leave blank to disable email alerts.",
                 bg=BG, fg=TEXT_SEC,
                 font=("Segoe UI", 8)).grid(
            row=1, column=0, columnspan=2, padx=20, sticky="w")

        keys = [
            ("SMTP Host",         "smtp_host",  "smtp.gmail.com"),
            ("SMTP Port",         "smtp_port",  "587"),
            ("SMTP Username",     "smtp_user",  "you@gmail.com"),
            ("SMTP Password",     "smtp_pass",  "app-password"),
            ("Alert Recipient",   "smtp_to",    "alert@yourteam.com"),
        ]
        vars_ = {}
        for i, (lbl, key, ph) in enumerate(keys):
            tk.Label(dlg, text=lbl, bg=BG, fg=TEXT_SEC,
                     font=("Segoe UI", 9)).grid(
                row=i+2, column=0, sticky="w", padx=20, pady=6)
            v = tk.StringVar(value=self.db.get_setting(key) or ph)
            show = "*" if "pass" in key.lower() else ""
            tk.Entry(dlg, textvariable=v, bg=BG_INPUT, fg=TEXT_PRI,
                     insertbackground=ACCENT, relief="flat",
                     font=("Consolas", 10), width=32, show=show).grid(
                row=i+2, column=1, padx=10, pady=6, sticky="ew")
            vars_[key] = v

        def save():
            for key, v in vars_.items():
                self.db.set_setting(key, v.get().strip())
            messagebox.showinfo("Saved", "Settings saved.", parent=dlg)
            dlg.destroy()

        tk.Button(dlg, text="Save", bg=ACCENT, fg="#fff",
                  relief="flat", font=("Segoe UI", 10, "bold"),
                  padx=20, pady=8, cursor="hand2",
                  command=save).grid(
            row=len(keys)+2, column=0, columnspan=2, pady=14)

    # ────────────────────────────────────────────────────
    def _on_close(self):
        self.engine.stop_all()
        self.db.conn.close()
        self.destroy()


# ════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = WatchdogApp()
    app.mainloop()
