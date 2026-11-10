<div align="center">

![Clearspace — Claude Local Cleanup](banner.svg)

# Clearspace

**A Windows and macOS preview for reviewing Claude-related local data and privacy settings.**

[中文说明](../README.md) · [Safety and recovery](SAFETY.md) · [Third-party notices](../THIRD_PARTY_NOTICES.md)

</div>

> **Deletion is permanent and has no backup.** Browser cleanup may remove cookies, caches, and site data for **all websites**, not just Claude. The restore action only attempts to restore certain DNS and browser location/language settings when a valid record exists. It cannot recover deleted data or guarantee a complete rollback.

Clearspace is an independent, unofficial project and is not affiliated with Anthropic. Local cleanup cannot erase server-side records, guarantee fingerprint removal, or change account eligibility.

## Interface

![Clearspace main screen before scanning](screenshot.png)

The main screen opens without scanning automatically. Browser, system, and network recovery controls have separate pages.

## Features

- Review discovered Claude Desktop and Claude Code data and select specific cleanup targets.
- Manage browser data, location, language, WebRTC, and AdGuard options; browser cleanup has a wider scope than Claude.
- Manage selected Claude environment variables and system DNS, location, time zone, and region settings.
- Review a combined scan and action plan before running it; conflicting or blocked items are reported.
- Inspect network recovery and attempt supported setting restoration when valid state is available.

## Getting started

Requirements: Windows 10/11 or macOS, Python 3.10+ with Tkinter, and Node.js 24.4+. No Electron or npm install is required. Some operations require administrator approval. The macOS preview supports Apple Silicon and Intel but has not been end-to-end validated on a real Mac desktop.

On Windows, download and extract the repository, then double-click `start.cmd`. Alternatively, clone and run it from a terminal:

```powershell
git clone https://github.com/Cheng02lema/clearspace.git
cd clearspace
python run.py
```

On macOS, install [Python with Tkinter](https://www.python.org/downloads/macos/) and [Node.js](https://nodejs.org/en/download), then run from the complete project directory:

```bash
chmod +x start-macos.command Clearspace.app/Contents/MacOS/clearspace
./start-macos.command
```

You can also open `Clearspace.app` in Finder. This is a source-tree launcher, not a self-contained app: keep it beside the other project files and install Python and Node.js separately. It is unsigned and not notarized, so macOS may restrict opening it. Running `python3 run.py` in Terminal is another source-run option.

Scan first, inspect each path and effect, save your work, and confirm before applying changes. The application is a preview: its UI and orchestration are Python, while the cleanup, browser, and DNS core still uses a JavaScript compatibility layer. It is **not yet a pure Python application**.

On macOS, discovery is limited to the current user's home and an explicitly configured `CLAUDE_CONFIG_DIR`. Safari and Keychain credentials are not cleaned. Windows-only DNS protection, AdGuard automation, browser language synchronization and network recovery are unavailable; one-click restore cannot currently undo macOS cleanup or system/browser settings. Cleaning Claude environment variables may remove matching entire lines from shell configuration files.

## Privacy and network use

Scanning and cleanup are local. Optional location and time-zone lookup uses `ipwho.is` or `ipapi.co`; DNS protection uses a Cloudflare connectivity check and configured DNS resolvers; AdGuard flows open official browser-store and configuration pages. The application is not fully offline.

## Tests

```powershell
python -m unittest discover -s tests -v
node --test tests/legacy-cleaner.test.js tests/browser-process.test.js tests/macos-platform.test.js
```

Tests use mocks and temporary files; they do not clean user data or change network settings. Real elevated DNS and browser policy changes have not been verified across all Windows environments.

Project code is available under the [MIT License](../LICENSE). Claude and Anthropic are names belonging to their respective owners. See [third-party notices](../THIRD_PARTY_NOTICES.md) for bundled DNSCrypt-Proxy license information.
