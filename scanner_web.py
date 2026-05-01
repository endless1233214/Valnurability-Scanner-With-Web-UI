#!/usr/bin/env python3
import argparse
import datetime as dt
import html
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT_DIR = Path(__file__).resolve().parent
BIN_DIR = ROOT_DIR / "bin"
REPORTS_DIR = ROOT_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

ENV = os.environ.copy()
ENV["PATH"] = f"{BIN_DIR}{os.pathsep}{ENV.get('PATH', '')}"

JOBS = {}
JOBS_LOCK = threading.RLock()

SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/,\-\[\]]+$")

WEB_PORTS = {
    80,
    81,
    443,
    591,
    593,
    8000,
    8008,
    8080,
    8081,
    8088,
    8090,
    8095,
    8123,
    8443,
    8834,
    8888,
    9000,
    9090,
    9443,
    10000,
    32400,
}

HTTPS_PORTS = {443, 8443, 8834, 9443}
WEB_SERVICE_NAMES = {
    "http",
    "https",
    "http-alt",
    "http-proxy",
    "ssl/http",
    "sun-answerbook",
}

PROFILES = {
    "fast-web": {
        "label": "Fast web/admin",
        "ports": "22,80,81,443,3000,5000,5001,7001,8000,8008,8080,8081,8088,8090,8095,8123,8443,8787,8834,8888,9000,9090,9443,10000,32400",
        "args": ["-sV", "--version-light", "--open", "-T3", "--host-timeout", "180s"],
        "run_nuclei": True,
    },
    "standard": {
        "label": "Standard",
        "ports": "",
        "args": ["-sV", "--version-light", "--open", "-T3", "--host-timeout", "300s"],
        "run_nuclei": True,
    },
    "inventory": {
        "label": "Inventory only",
        "ports": "",
        "args": ["-sn"],
        "run_nuclei": False,
    },
}


def now_iso():
    return dt.datetime.now().replace(microsecond=0).isoformat()


def tool_path(name):
    return shutil.which(name, path=ENV["PATH"])


def public_job(job):
    with JOBS_LOCK:
        return {
            "id": job["id"],
            "status": job["status"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "target_preview": job["target_preview"],
            "profile": job["profile"],
            "log": list(job["log"][-500:]),
            "summary": dict(job.get("summary", {})),
            "artifacts": dict(job.get("artifacts", {})),
            "error": job.get("error", ""),
        }


def set_job(job, **changes):
    with JOBS_LOCK:
        job.update(changes)
        job["updated_at"] = now_iso()


def append_log(job, message):
    line = message.rstrip("\n")
    with JOBS_LOCK:
        job["log"].append(line)
        job["updated_at"] = now_iso()
    with open(job["report_dir"] / "scan.log", "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def normalize_targets(raw):
    lines = []
    for line in raw.replace(",", "\n").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        if len(item) > 300 or not SAFE_TARGET_RE.match(item):
            raise ValueError(f"Unsafe or unsupported target text: {item!r}")
        lines.append(item)

    if not lines:
        raise ValueError("Add at least one target.")
    if len(lines) > 1000:
        raise ValueError("Too many targets for one UI scan. Keep it under 1000.")

    nmap_targets = []
    seed_urls = []
    for item in lines:
        parsed = urlparse(item)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            seed_urls.append(item.rstrip("/"))
            nmap_targets.append(parsed.hostname)
        else:
            nmap_targets.append(item)

    return lines, sorted(set(nmap_targets)), sorted(set(seed_urls))


def run_command(job, cmd, cwd):
    append_log(job, "")
    append_log(job, f"$ {shlex.join(cmd)}")
    started = time.time()

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        append_log(job, f"[missing] {cmd[0]} is not installed or not on PATH.")
        return 127

    assert proc.stdout is not None
    for line in proc.stdout:
        append_log(job, line)

    rc = proc.wait()
    elapsed = time.time() - started
    append_log(job, f"[exit {rc}] {cmd[0]} finished in {elapsed:.1f}s")
    return rc


def host_label(host):
    addr = host.find("address")
    if addr is not None and addr.attrib.get("addr"):
        return addr.attrib["addr"]
    hostname = host.find("./hostnames/hostname")
    if hostname is not None and hostname.attrib.get("name"):
        return hostname.attrib["name"]
    return "unknown"


def parse_nmap_xml(xml_path):
    summary = {
        "hosts_seen": 0,
        "open_ports": 0,
        "web_targets": [],
        "ports": [],
    }

    if not xml_path.exists():
        return summary

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return summary

    for host in root.findall("host"):
        address = host_label(host)
        status = host.find("status")
        if status is not None and status.attrib.get("state") == "up":
            summary["hosts_seen"] += 1

        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            proto = port.attrib.get("protocol", "tcp")
            port_id = int(port.attrib.get("portid", "0"))
            service = port.find("service")
            service_name = service.attrib.get("name", "") if service is not None else ""
            product = service.attrib.get("product", "") if service is not None else ""
            version = service.attrib.get("version", "") if service is not None else ""
            tunnel = service.attrib.get("tunnel", "") if service is not None else ""

            summary["open_ports"] += 1
            summary["ports"].append(
                {
                    "host": address,
                    "port": port_id,
                    "proto": proto,
                    "service": service_name,
                    "product": product,
                    "version": version,
                }
            )

            is_web = (
                port_id in WEB_PORTS
                or service_name in WEB_SERVICE_NAMES
                or "http" in service_name
            )
            if is_web and proto == "tcp":
                scheme = "https" if tunnel == "ssl" or port_id in HTTPS_PORTS or service_name == "https" else "http"
                if ":" in address and not address.startswith("["):
                    address_for_url = f"[{address}]"
                else:
                    address_for_url = address
                summary["web_targets"].append(f"{scheme}://{address_for_url}:{port_id}")

    summary["web_targets"] = sorted(set(summary["web_targets"]))
    return summary


def count_nuclei_findings(path):
    if not path.exists():
        return 0
    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def html_report(job, summary):
    ports = summary.get("ports", [])
    findings = summary.get("nuclei_findings", 0)
    web_targets = summary.get("web_targets", [])

    rows = []
    for port in ports[:1000]:
        service = " ".join(part for part in [port.get("service"), port.get("product"), port.get("version")] if part)
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(port.get('host', '')))}</td>"
            f"<td>{html.escape(str(port.get('port', '')))}</td>"
            f"<td>{html.escape(str(port.get('proto', '')))}</td>"
            f"<td>{html.escape(service)}</td>"
            "</tr>"
        )

    url_rows = "".join(f"<li>{html.escape(url)}</li>" for url in web_targets[:500])
    port_rows = "\n".join(rows) or '<tr><td colspan="4">No open ports parsed.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Scan Report {html.escape(job["id"])}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #172026; }}
    h1 {{ font-size: 24px; }}
    h2 {{ font-size: 18px; margin-top: 28px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #d7dde2; padding: 8px; text-align: left; font-size: 14px; }}
    th {{ background: #eef3f7; }}
    code, pre {{ background: #f4f6f8; padding: 2px 4px; border-radius: 4px; }}
    .metrics {{ display: flex; gap: 14px; flex-wrap: wrap; }}
    .metric {{ border: 1px solid #cfd8df; padding: 10px 12px; border-radius: 6px; min-width: 140px; }}
    .metric b {{ display: block; font-size: 22px; }}
  </style>
</head>
<body>
  <h1>Scan Report</h1>
  <p><b>Job:</b> {html.escape(job["id"])}<br><b>Created:</b> {html.escape(job["created_at"])}<br><b>Status:</b> {html.escape(job["status"])}</p>
  <div class="metrics">
    <div class="metric"><b>{summary.get("hosts_seen", 0)}</b> hosts up</div>
    <div class="metric"><b>{summary.get("open_ports", 0)}</b> open ports</div>
    <div class="metric"><b>{len(web_targets)}</b> web targets</div>
    <div class="metric"><b>{findings}</b> nuclei lines</div>
  </div>
  <h2>Artifacts</h2>
  <ul>
    <li><a href="scan.log">scan.log</a></li>
    <li><a href="nmap.nmap">nmap.nmap</a></li>
    <li><a href="nmap.xml">nmap.xml</a></li>
    <li><a href="web_targets.txt">web_targets.txt</a></li>
    <li><a href="nuclei.txt">nuclei.txt</a></li>
    <li><a href="summary.json">summary.json</a></li>
  </ul>
  <h2>Web Targets</h2>
  <ul>{url_rows or "<li>None discovered.</li>"}</ul>
  <h2>Open Ports</h2>
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Service</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>
</body>
</html>
"""


def run_scan(job, request):
    try:
        set_job(job, status="running")
        report_dir = job["report_dir"]

        raw_targets, nmap_targets, seed_urls = normalize_targets(request["targets"])
        profile_name = request.get("profile", "fast-web")
        profile = PROFILES.get(profile_name, PROFILES["fast-web"])
        custom_ports = request.get("ports", "").strip()
        severities = request.get("severities", ["critical", "high", "medium"])
        if isinstance(severities, str):
            severities = [item.strip() for item in severities.split(",") if item.strip()]
        severities = [s for s in severities if s in {"critical", "high", "medium", "low", "info", "unknown"}]
        if not severities:
            severities = ["critical", "high", "medium"]

        skip_host_discovery = bool(request.get("skip_host_discovery", False))
        include_intrusive = bool(request.get("include_intrusive", False))
        update_templates = bool(request.get("update_templates", False))
        run_nuclei = bool(request.get("run_nuclei", profile["run_nuclei"]))

        targets_path = report_dir / "targets.txt"
        nmap_targets_path = report_dir / "nmap_targets.txt"
        web_targets_path = report_dir / "web_targets.txt"

        targets_path.write_text("\n".join(raw_targets) + "\n", encoding="utf-8")
        nmap_targets_path.write_text("\n".join(nmap_targets) + "\n", encoding="utf-8")

        append_log(job, f"Created report folder: {report_dir}")
        append_log(job, f"Profile: {profile['label']}")
        append_log(job, f"Targets: {', '.join(raw_targets[:8])}{' ...' if len(raw_targets) > 8 else ''}")

        if not tool_path("nmap"):
            append_log(job, "[missing] nmap is required. Run sh setup_scanner.sh.")
            set_job(job, status="failed", error="nmap missing")
            return

        nmap_prefix = report_dir / "nmap"
        nmap_cmd = ["nmap", *profile["args"]]
        ports = custom_ports or profile["ports"]
        if ports:
            nmap_cmd.extend(["-p", ports])
        if skip_host_discovery and "-sn" not in profile["args"]:
            nmap_cmd.append("-Pn")
        nmap_cmd.extend(["-oA", str(nmap_prefix), "-iL", str(nmap_targets_path)])
        rc = run_command(job, nmap_cmd, report_dir)
        if rc not in (0, 1):
            append_log(job, "[warn] Nmap returned a non-zero exit. Continuing with whatever output exists.")

        summary = parse_nmap_xml(report_dir / "nmap.xml")
        web_targets = sorted(set(seed_urls + summary["web_targets"]))
        web_targets_path.write_text("\n".join(web_targets) + ("\n" if web_targets else ""), encoding="utf-8")
        summary["web_targets"] = web_targets
        append_log(job, f"Parsed {summary['open_ports']} open ports and {len(web_targets)} web targets.")

        if update_templates and tool_path("nuclei"):
            run_command(job, ["nuclei", "-update-templates"], report_dir)

        nuclei_out = report_dir / "nuclei.txt"
        nuclei_out.touch(exist_ok=True)
        if run_nuclei and web_targets:
            if not tool_path("nuclei"):
                append_log(job, "[missing] nuclei is not installed. Run sh setup_scanner.sh.")
            else:
                nuclei_cmd = [
                    "nuclei",
                    "-l",
                    str(web_targets_path),
                    "-severity",
                    ",".join(severities),
                    "-o",
                    str(nuclei_out),
                ]
                if not include_intrusive:
                    nuclei_cmd.extend(["-exclude-tags", "destructive,dos,intrusive"])
                run_command(job, nuclei_cmd, report_dir)
        elif run_nuclei and not web_targets:
            append_log(job, "No web targets discovered, so Nuclei was skipped.")
        else:
            append_log(job, "Nuclei disabled for this scan.")

        summary["nuclei_findings"] = count_nuclei_findings(nuclei_out)
        summary_path = report_dir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        report_path = report_dir / "report.html"
        report_path.write_text(html_report(job, summary), encoding="utf-8")

        artifacts = {
            "report": f"/reports/{report_dir.name}/report.html",
            "log": f"/reports/{report_dir.name}/scan.log",
            "nmap": f"/reports/{report_dir.name}/nmap.nmap",
            "nmap_xml": f"/reports/{report_dir.name}/nmap.xml",
            "web_targets": f"/reports/{report_dir.name}/web_targets.txt",
            "nuclei": f"/reports/{report_dir.name}/nuclei.txt",
            "summary": f"/reports/{report_dir.name}/summary.json",
        }
        set_job(job, status="done", summary=summary, artifacts=artifacts)
        append_log(job, f"Report: {artifacts['report']}")
    except Exception as exc:
        append_log(job, f"[error] {exc}")
        set_job(job, status="failed", error=str(exc))


def start_job(request):
    raw_targets, _, _ = normalize_targets(request.get("targets", ""))
    job_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    report_dir = REPORTS_DIR / job_id
    report_dir.mkdir(parents=True, exist_ok=True)

    job = {
        "id": job_id,
        "status": "queued",
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "target_preview": ", ".join(raw_targets[:4]) + (" ..." if len(raw_targets) > 4 else ""),
        "profile": request.get("profile", "fast-web"),
        "log": [],
        "summary": {},
        "artifacts": {},
        "report_dir": report_dir,
    }
    with JOBS_LOCK:
        JOBS[job_id] = job

    thread = threading.Thread(target=run_scan, args=(job, request), daemon=True)
    thread.start()
    return public_job(job)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Free Vulnerability Scanner</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fa;
      --surface: #ffffff;
      --line: #cfd8df;
      --line-strong: #aab8c2;
      --text: #172026;
      --muted: #60707c;
      --accent: #116b5f;
      --accent-dark: #0b5148;
      --danger: #9d2f2f;
      --warn: #8a5a00;
      --ok: #17633b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    header {
      border-bottom: 1px solid var(--line);
      background: var(--surface);
      padding: 14px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    h1 {
      font-size: 18px;
      margin: 0;
      font-weight: 700;
    }
    .tools {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .tool {
      border: 1px solid var(--line);
      background: #eef3f7;
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 12px;
      color: var(--muted);
    }
    .tool.ok { color: var(--ok); border-color: #8ec2a6; background: #edf8f1; }
    .tool.missing { color: var(--danger); border-color: #dbaaaa; background: #fff1f1; }
    main {
      display: grid;
      grid-template-columns: minmax(320px, 420px) minmax(0, 1fr);
      gap: 18px;
      padding: 18px;
      max-width: 1400px;
      margin: 0 auto;
    }
    section {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 6px;
      min-width: 0;
    }
    section h2 {
      margin: 0;
      padding: 12px 14px;
      font-size: 14px;
      border-bottom: 1px solid var(--line);
    }
    form {
      padding: 14px;
      display: grid;
      gap: 12px;
    }
    label {
      display: grid;
      gap: 6px;
      font-size: 13px;
      font-weight: 650;
    }
    textarea, input, select {
      width: 100%;
      border: 1px solid var(--line-strong);
      border-radius: 4px;
      background: #fff;
      color: var(--text);
      padding: 8px 9px;
      font: inherit;
      font-size: 14px;
    }
    textarea {
      min-height: 142px;
      resize: vertical;
      line-height: 1.35;
    }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }
    .checks {
      display: grid;
      gap: 7px;
      font-size: 13px;
    }
    .checks label {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 500;
    }
    input[type="checkbox"] {
      width: 16px;
      height: 16px;
    }
    button {
      border: 0;
      border-radius: 4px;
      background: var(--accent);
      color: white;
      padding: 10px 12px;
      font-weight: 700;
      cursor: pointer;
    }
    button:hover { background: var(--accent-dark); }
    button:disabled { opacity: 0.55; cursor: wait; }
    .note {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
      margin: 0;
    }
    .jobs {
      display: grid;
      grid-template-rows: auto minmax(260px, 1fr);
      min-height: 640px;
    }
    .jobbar {
      display: flex;
      gap: 8px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      overflow-x: auto;
    }
    .jobtab {
      border: 1px solid var(--line);
      background: #f8fafb;
      color: var(--text);
      padding: 8px 10px;
      border-radius: 4px;
      min-width: 190px;
      text-align: left;
      cursor: pointer;
    }
    .jobtab.active {
      border-color: var(--accent);
      box-shadow: inset 0 0 0 1px var(--accent);
    }
    .jobtab b {
      display: block;
      font-size: 13px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .jobtab span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      margin-top: 2px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .details {
      padding: 14px;
      display: grid;
      gap: 12px;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(100px, 1fr));
      gap: 10px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 10px;
      background: #fbfcfd;
      min-height: 70px;
    }
    .metric b {
      display: block;
      font-size: 24px;
      line-height: 1;
      margin-bottom: 7px;
    }
    .metric span {
      color: var(--muted);
      font-size: 12px;
    }
    .status {
      display: inline-flex;
      width: fit-content;
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 700;
      background: #eef3f7;
      color: var(--muted);
      border: 1px solid var(--line);
    }
    .status.done { color: var(--ok); background: #edf8f1; border-color: #8ec2a6; }
    .status.failed { color: var(--danger); background: #fff1f1; border-color: #dbaaaa; }
    .status.running, .status.queued { color: var(--warn); background: #fff7e5; border-color: #d6b46b; }
    .links {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .links a {
      color: var(--accent-dark);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 7px 9px;
      text-decoration: none;
      background: #fbfcfd;
      font-size: 13px;
    }
    pre {
      margin: 0;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: #111820;
      color: #d8e2ea;
      padding: 12px;
      min-height: 310px;
      max-height: 520px;
      overflow: auto;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    @media (max-width: 860px) {
      header { align-items: flex-start; flex-direction: column; }
      main { grid-template-columns: 1fr; padding: 12px; }
      .row, .metrics { grid-template-columns: 1fr; }
      .jobs { min-height: 480px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Free Vulnerability Scanner</h1>
    <div class="tools" id="tools"></div>
  </header>
  <main>
    <section>
      <h2>New Scan</h2>
      <form id="scanForm">
        <label>
          Targets
          <textarea id="targets" name="targets" spellcheck="false">192.168.1.0/24</textarea>
        </label>
        <div class="row">
          <label>
            Profile
            <select id="profile" name="profile">
              <option value="fast-web">Fast web/admin</option>
              <option value="standard">Standard</option>
              <option value="inventory">Inventory only</option>
            </select>
          </label>
          <label>
            Custom ports
            <input id="ports" name="ports" placeholder="optional, e.g. 22,80,443,8123">
          </label>
        </div>
        <label>
          Nuclei severities
          <input id="severities" name="severities" value="critical,high,medium">
        </label>
        <div class="checks">
          <label><input id="skipHostDiscovery" type="checkbox"> Treat hosts as up (-Pn)</label>
          <label><input id="runNuclei" type="checkbox" checked> Run Nuclei on discovered web targets</label>
          <label><input id="updateTemplates" type="checkbox"> Update Nuclei templates first</label>
          <label><input id="includeIntrusive" type="checkbox"> Allow intrusive/destructive/DoS-tagged templates</label>
        </div>
        <p class="note">Scan only systems you own or have permission to test. Local-only issues such as Copy Fail need local patch checks.</p>
        <button id="startButton" type="submit">Start Scan</button>
      </form>
    </section>
    <section class="jobs">
      <h2>Jobs</h2>
      <div class="jobbar" id="jobbar"></div>
      <div class="details" id="details">
        <span class="status">idle</span>
        <div class="metrics">
          <div class="metric"><b>0</b><span>hosts up</span></div>
          <div class="metric"><b>0</b><span>open ports</span></div>
          <div class="metric"><b>0</b><span>web targets</span></div>
          <div class="metric"><b>0</b><span>nuclei lines</span></div>
        </div>
        <div class="links"></div>
        <pre>No scan selected.</pre>
      </div>
    </section>
  </main>
  <script>
    const state = { jobs: [], selected: null, busy: false };

    function esc(value) {
      return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[ch]));
    }

    async function api(path, options = {}) {
      const res = await fetch(path, {
        headers: { 'Content-Type': 'application/json' },
        ...options
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      return res.json();
    }

    async function loadTools() {
      const data = await api('/api/tools');
      const tools = document.getElementById('tools');
      tools.innerHTML = Object.entries(data.tools).map(([name, path]) => {
        const ok = Boolean(path);
        return `<span class="tool ${ok ? 'ok' : 'missing'}">${esc(name)}: ${ok ? 'ok' : 'missing'}</span>`;
      }).join('');
    }

    async function loadJobs() {
      const data = await api('/api/jobs');
      state.jobs = data.jobs;
      if (!state.selected && state.jobs.length) state.selected = state.jobs[0].id;
      renderJobs();
      if (state.selected) await loadJob(state.selected);
    }

    async function loadJob(id) {
      const job = await api(`/api/jobs/${encodeURIComponent(id)}`);
      state.selected = id;
      renderDetails(job);
      renderJobs();
    }

    function renderJobs() {
      const bar = document.getElementById('jobbar');
      if (!state.jobs.length) {
        bar.innerHTML = '<span class="note">No scans yet.</span>';
        return;
      }
      bar.innerHTML = state.jobs.map(job => `
        <button class="jobtab ${job.id === state.selected ? 'active' : ''}" data-id="${esc(job.id)}" type="button">
          <b>${esc(job.status)} · ${esc(job.id)}</b>
          <span>${esc(job.target_preview)}</span>
        </button>
      `).join('');
      for (const btn of bar.querySelectorAll('.jobtab')) {
        btn.addEventListener('click', () => loadJob(btn.dataset.id));
      }
    }

    function renderDetails(job) {
      const s = job.summary || {};
      const artifacts = job.artifacts || {};
      const details = document.getElementById('details');
      const links = Object.entries(artifacts).map(([name, href]) => (
        `<a href="${esc(href)}" target="_blank" rel="noreferrer">${esc(name)}</a>`
      )).join('');
      details.innerHTML = `
        <span class="status ${esc(job.status)}">${esc(job.status)}</span>
        <div class="metrics">
          <div class="metric"><b>${esc(s.hosts_seen || 0)}</b><span>hosts up</span></div>
          <div class="metric"><b>${esc(s.open_ports || 0)}</b><span>open ports</span></div>
          <div class="metric"><b>${esc((s.web_targets || []).length || 0)}</b><span>web targets</span></div>
          <div class="metric"><b>${esc(s.nuclei_findings || 0)}</b><span>nuclei lines</span></div>
        </div>
        <div class="links">${links}</div>
        <pre>${esc((job.log || []).join('\n'))}</pre>
      `;
      const pre = details.querySelector('pre');
      pre.scrollTop = pre.scrollHeight;
    }

    document.getElementById('scanForm').addEventListener('submit', async event => {
      event.preventDefault();
      const button = document.getElementById('startButton');
      button.disabled = true;
      try {
        const payload = {
          targets: document.getElementById('targets').value,
          profile: document.getElementById('profile').value,
          ports: document.getElementById('ports').value,
          severities: document.getElementById('severities').value,
          skip_host_discovery: document.getElementById('skipHostDiscovery').checked,
          run_nuclei: document.getElementById('runNuclei').checked,
          update_templates: document.getElementById('updateTemplates').checked,
          include_intrusive: document.getElementById('includeIntrusive').checked
        };
        const job = await api('/api/scan', { method: 'POST', body: JSON.stringify(payload) });
        state.selected = job.id;
        await loadJobs();
      } catch (err) {
        alert(err.message);
      } finally {
        button.disabled = false;
      }
    });

    setInterval(loadJobs, 2500);
    loadTools().catch(console.error);
    loadJobs().catch(console.error);
  </script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "FreeVulnScanner/0.1"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, status=200, content_type="text/plain; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            self.send_text(INDEX_HTML, content_type="text/html; charset=utf-8")
            return

        if path == "/api/tools":
            self.send_json(
                {
                    "tools": {
                        "python3": tool_path("python3"),
                        "nmap": tool_path("nmap"),
                        "nuclei": tool_path("nuclei"),
                        "httpx": tool_path("httpx"),
                        "naabu": tool_path("naabu"),
                    }
                }
            )
            return

        if path == "/api/jobs":
            with JOBS_LOCK:
                jobs = [public_job(job) for job in sorted(JOBS.values(), key=lambda item: item["created_at"], reverse=True)]
            self.send_json({"jobs": jobs})
            return

        if path.startswith("/api/jobs/"):
            job_id = unquote(path.rsplit("/", 1)[-1])
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                self.send_json({"error": "job not found"}, status=404)
                return
            self.send_json(public_job(job))
            return

        if path.startswith("/reports/"):
            rel = Path(unquote(path[len("/reports/") :]))
            if rel.is_absolute() or ".." in rel.parts:
                self.send_text("bad path", status=400)
                return
            file_path = REPORTS_DIR / rel
            if not file_path.is_file():
                self.send_text("not found", status=404)
                return
            content_type = "text/plain; charset=utf-8"
            if file_path.suffix == ".html":
                content_type = "text/html; charset=utf-8"
            elif file_path.suffix == ".json":
                content_type = "application/json; charset=utf-8"
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_text("not found", status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/scan":
            self.send_text("not found", status=404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8") or "{}")
            job = start_job(payload)
            self.send_json(job, status=201)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=500)


def main():
    parser = argparse.ArgumentParser(description="Local web UI for Nmap + Nuclei scanning.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("Warning: this UI has no authentication. Put it behind auth if you bind beyond localhost.")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Scanner UI running at http://{args.host}:{args.port}")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
