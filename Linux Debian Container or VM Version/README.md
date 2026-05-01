# Debian Container or VM Scanner

This is the server-friendly version of the free vulnerability scanner. Run this
on a Debian server, Debian VM, Proxmox VM, or a Linux Docker host when the server
has more CPU/network access than the Mac.

Recommended path:

```sh
cd "/path/to/Linux Debian Container or VM Version"
sh scripts/build-and-run.sh
```

Then open:

```text
http://SERVER-IP:8788
```

Keep this UI private. It has no login screen. Use LAN-only access, VPN, Tailscale,
or an SSH tunnel instead of exposing it to the public internet.

## Option 1: Debian Docker Host

This is best for a home server.

Requirements on the server:

- Debian or another Linux host
- Docker Engine
- Docker Compose plugin, or old `docker-compose`

Start:

```sh
sh scripts/build-and-run.sh
```

Watch logs:

```sh
sh scripts/logs.sh
```

Stop:

```sh
sh scripts/stop.sh
```

Reports are saved here:

```text
data/reports/
```

Nuclei templates and cache are saved here:

```text
data/projectdiscovery/
```

The container uses `network_mode: host` so LAN discovery works properly from a
Linux server. This is why this version is better on the server than Docker on
macOS.

## Option 1B: TrueNAS Custom App

After the GitHub Actions workflow publishes the container image, use this file
in TrueNAS SCALE's Install via YAML screen:

```text
truenas-compose-ghcr.yml
```

Change `/mnt/YOUR_POOL/apps/free-vuln-scanner` to the dataset path you want to
use for reports and Nuclei template/cache data.

## Option 2: Native Debian VM

Use this if you do not want Docker.

```sh
sh scripts/setup-debian-vm.sh
sh scripts/run-vm-ui.sh
```

Then open:

```text
http://VM-IP:8788
```

The VM script installs Debian packages with `apt` and downloads the official
ProjectDiscovery release binaries for `nuclei`, `httpx`, and `naabu` into
`./bin`.

## Scanner Behavior

The web UI runs Nmap first, parses discovered web-ish services, then runs Nuclei
against those web targets unless you disable it.

Default safety settings:

- Nuclei excludes `destructive`, `dos`, and `intrusive` templates.
- The UI is not authenticated, so keep it private.
- It does not run exploit PoCs.

## Copy Fail

Copy Fail / CVE-2026-31431 is a local Linux kernel issue. A network scanner
cannot safely prove it. For Linux hosts you control:

```sh
sh copy_fail_check.sh
sudo sh copy_fail_mitigate.sh --apply
```

Patch kernels and reboot when your distro provides updates.

## Useful First Scan

For a normal home LAN:

```text
192.168.1.0/24
```

Profile:

```text
Fast web/admin
```

Leave intrusive/destructive templates off.
