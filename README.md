# Free Vulnerability Scanner

This is a lightweight, free scanner stack for systems you own. It is meant to
feel closer to an OpenVAS-style workflow without running a heavy GVM appliance.

It uses:

- Nmap for host and service discovery
- Nuclei for CVE, exposure, misconfiguration, and web checks
- A small local web UI for starting scans and reading reports
- Local files for reports, so nothing is sent to a cloud service

Important: this is a vulnerability finder, not an exploit runner. Some bugs,
including Copy Fail / CVE-2026-31431, cannot be proven safely from the network.
For those, use local package/kernel checks and vendor patches.

## Quick Start

Install tools:

```sh
sh setup_scanner.sh
```

Start the web UI:

```sh
sh run_web.sh
```

Open:

```text
http://127.0.0.1:8788
```

The UI binds to localhost by default and has no login system. Keep it local
unless you put it behind proper authentication.

## Debian Server Version

For a stronger server, VM, or Linux Docker host, use:

```text
Linux Debian Container or VM Version/
```

That folder has a Docker Compose setup and a native Debian VM setup. It binds
the UI on `0.0.0.0:8788` so you can reach it from another machine on your LAN or
private VPN.

## GitHub / TrueNAS

This repo is prepared to publish a container image to:

```text
ghcr.io/endless1233214/valnurability-scanner-with-web-ui:latest
```

Use [TRUENAS.md](TRUENAS.md) for the TrueNAS custom app path.
Use [GITHUB.md](GITHUB.md) for the first push and GHCR notes.

The intended setup is the same pattern as PlainNVR: private GitHub repo, GitHub
Actions publishes `latest` to GHCR, and TrueNAS pulls that image.

## Good Targets

Use only systems you own or have permission to test.

Examples:

```text
192.168.1.0/24
192.168.1.10
https://homeassistant.local:8123
https://example.internal
```

## Scan Profiles

Fast web/admin:

- Common web and admin ports
- Good for homelab devices and dashboards
- Runs Nuclei against discovered web URLs

Standard:

- Nmap default top ports with service detection
- Good general baseline
- Runs Nuclei against discovered web URLs

Inventory only:

- Ping sweep only
- No vulnerability templates
- Useful before you decide what to scan harder

## What This Will Catch Well

- Exposed admin panels
- Known vulnerable web apps and devices covered by Nuclei templates
- Default pages, misconfigurations, leaked files, weak service exposure
- Open ports and service versions for manual review

## What This Will Not Catch Reliably

- Local-only kernel privilege escalations like Copy Fail
- Missing OS packages without authenticated local checks
- Vulnerabilities that need credentials to validate
- Business-logic bugs
- Anything hidden behind strict firewalls or VPN routes the scanner cannot see

## Copy Fail Note

For Copy Fail specifically, patch Linux kernels and/or disable `algif_aead`.
Use:

```sh
sh copy_fail_check.sh
sudo sh copy_fail_mitigate.sh --apply
```

Do not run the public Copy Fail exploit as a checker.

## Output

Each scan gets its own folder under:

```text
reports/
```

Typical files:

- `scan.log`
- `nmap.xml`
- `nmap.nmap`
- `web_targets.txt`
- `nuclei.txt`
- `summary.json`
- `report.html`
