<div align="center">

![Clearspace — Claude Local Cleanup](banner.svg)

# Clearspace

**A Windows preview for reviewing Claude-related local data and privacy settings.**

[中文说明](../README.md) · [Safety and recovery](SAFETY.md) · [Third-party notices](../THIRD_PARTY_NOTICES.md)

</div>

> **Deletion is permanent and has no backup.** Browser cleanup may remove cookies, caches, and site data for **all websites**, not just Claude. The restore action only attempts to restore certain DNS and browser location/language settings when a valid record exists. It cannot recover deleted data or guarantee a complete rollback.

Clearspace is an independent, unofficial project and is not affiliated with Anthropic. Local cleanup cannot erase server-side records, guarantee fingerprint removal, or change account eligibility.

## Features

- Review discovered Claude Desktop and Claude Code data and select specific cleanup targets.
- Manage browser data, location, language, WebRTC, and AdGuard options; browser cleanup has a wider scope than Claude.
- Manage selected Claude environment variables and system DNS, location, time zone, and region settings.
- Review a combined scan and action plan before running it; conflicting or blocked items are reported.
- Inspect network recovery and attempt supported setting restoration when valid state is available.

## Getting started

Requirements: Windows 10/11, Python 3.10+ with Tkinter, and Node.js 24.4+. No Electron or npm install is required. Some operations require administrator approval.

Download and extract the repository, then double-click `start.cmd`. Alternatively, clone and run it from a terminal:

```powershell
git clone https://github.com/Cheng02lema/clearspace.git
cd clearspace
python run.py
```

Scan first, inspect each path and effect, save your work, and confirm before applying changes. The application is a preview: its UI and orchestration are Python, while the cleanup, browser, and DNS core still uses a JavaScript compatibility layer. It is **not yet a pure Python application**.

## Privacy and network use

Scanning and cleanup are local. Optional location and time-zone lookup uses `ipwho.is` or `ipapi.co`; DNS protection uses a Cloudflare connectivity check and configured DNS resolvers; AdGuard flows open official browser-store and configuration pages. The application is not fully offline.

## Tests

```powershell
python -m unittest discover -s tests -v
node --test tests/legacy-cleaner.test.js tests/browser-process.test.js
```

Tests use mocks and temporary files; they do not clean user data or change network settings. Real elevated DNS and browser policy changes have not been verified across all Windows environments.

Project code is available under the [MIT License](../LICENSE). Claude and Anthropic are names belonging to their respective owners. See [third-party notices](../THIRD_PARTY_NOTICES.md) for bundled DNSCrypt-Proxy license information.
