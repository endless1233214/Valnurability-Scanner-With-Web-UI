# TrueNAS App Setup

Yes, this project is worth putting on GitHub if you want to run it cleanly on
TrueNAS. The useful path is:

1. Push this repo to GitHub.
2. Let GitHub Actions build the container image.
3. Use the GHCR image in TrueNAS as a custom app.

The image name this repo is prepared for is:

```text
ghcr.io/endless1233214/valnurability-scanner-with-web-ui:latest
```

## TrueNAS SCALE Install Via YAML

In TrueNAS SCALE:

1. Go to Apps.
2. Choose Custom App.
3. Use the menu option for Install via YAML.
4. Paste the YAML from:

```text
Linux Debian Container or VM Version/truenas-compose-ghcr.yml
```

Before saving, replace:

```text
/mnt/YOUR_POOL/apps/free-vuln-scanner
```

with the real dataset path you want to use.

Example:

```text
/mnt/tank/apps/free-vuln-scanner
```

Then create these datasets or directories on TrueNAS:

```text
/mnt/tank/apps/free-vuln-scanner/reports
/mnt/tank/apps/free-vuln-scanner/projectdiscovery
```

## Network Choice

This scanner uses host networking on TrueNAS because LAN discovery tools work
better when the container sees the server's real network stack.

Do not publish this UI to the internet. Keep it LAN-only or behind Tailscale/VPN.

## Updating

When a new commit lands on `main`, GitHub Actions builds and pushes:

```text
ghcr.io/endless1233214/valnurability-scanner-with-web-ui:latest
```

In TrueNAS, use pull policy `Always` for the custom app so redeploying pulls the
new image.

## Public vs Private GHCR

TrueNAS can pull a public GHCR image with no extra work. If the GHCR package is
private, add registry credentials in TrueNAS or make the package public in
GitHub's package settings.
