# GitHub Publishing

This repo is ready to publish to GitHub as:

```text
endless1233214/vuln-scanner-thingy
```

The local git remote is already set to:

```text
git@github.com:endless1233214/vuln-scanner-thingy.git
```

## Manual Path

1. Create a new empty repo on GitHub named:

```text
vuln-scanner-thingy
```

2. Do not add a README, license, or `.gitignore` on GitHub. This local repo
   already has those project files.

3. Push:

```sh
git push -u origin main
```

## GitHub CLI Path

If you install and authenticate GitHub CLI:

```sh
brew install gh
gh auth login
gh repo create endless1233214/vuln-scanner-thingy --private --source=. --remote=origin --push
```

## GHCR Image

After the first push to `main`, GitHub Actions should build:

```text
ghcr.io/endless1233214/vuln-scanner-thingy:latest
```

For TrueNAS, the easiest path is a public GHCR package. If the repo or package
is private, TrueNAS needs registry credentials to pull it.

This matches the PlainNVR pattern:

```text
private GitHub repo -> GitHub Actions -> GHCR latest image -> TrueNAS pull_policy always
```
