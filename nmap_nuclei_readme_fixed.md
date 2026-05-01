# Nmap + Nuclei Scanner Notes

This is a corrected version of the original README. The goal is a free general
vulnerability scanner, similar in spirit to OpenVAS/GVM, but lighter.

Use this repo's web UI when possible:

```sh
sh setup_scanner.sh
sh run_web.sh
```

Then open:

```text
http://127.0.0.1:8788
```

## What the scanner does

- Nmap finds hosts, ports, and service versions.
- The web UI turns discovered HTTP-like ports into URL targets.
- Nuclei checks those URLs with community templates.
- Reports are saved locally under `reports/`.

## What it is not

It is not a magic exploit button. It does not safely prove every CVE. Local-only
bugs such as Copy Fail / CVE-2026-31431 still need local package/kernel checks,
patches, and mitigations.

## CLI baseline

Create targets:

```sh
printf '%s\n' '192.168.1.0/24' > targets.txt
```

Run Nmap:

```sh
nmap -sV --open -T3 -oA nmap_results -iL targets.txt
```

Run Nuclei against known web URLs:

```sh
nuclei -update-templates
nuclei -l web_targets.txt -severity critical,high,medium -exclude-tags destructive,dos,intrusive -o nuclei_results.txt
```

## Docker note

Docker is convenient, but it can make local network discovery weird on macOS
because containers do not sit on your LAN the same way the Mac does. For home
LAN scans, native Nmap on the Mac or a Linux VM is usually cleaner.

## Safety defaults

- Scan only systems you own or have permission to test.
- Start with `Fast web/admin` or `Standard` in the web UI.
- Keep destructive, DoS, and intrusive Nuclei templates excluded unless you know
  exactly why you need them.
- Do not use public exploit PoCs as vulnerability checks.
