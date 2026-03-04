# openauth-totp

Minimal TOTP 2FA code generator. One command copies your current code to the clipboard. Bind it to a global hotkey for two-keystroke 2FA from any app.

## Install

```bash
pip install openauth-totp
```

Or install from source:

```bash
git clone https://github.com/rhakim/openauth-totp.git
cd openauth-totp
pip install .
```

## Quick start

```bash
# 1. Save your Base32 secret (one-time)
openauth --setup

# 2. Copy current code to clipboard
openauth
```

That's it. Run `openauth` whenever you need a code, then paste it.

## Requirements

- **Python 3.10+** (only the standard library — zero pip dependencies)
- **A clipboard tool** (built-in on macOS and Windows):
  - macOS: `pbcopy` (pre-installed)
  - Windows: `clip` (pre-installed)
  - Linux: `xclip` or `xsel` (`sudo apt install xclip`)
- **A browser** (optional, only for `--gui` mode):
  - Chrome or Chromium gives a clean app-style window (no tabs/URL bar)
  - Any other browser works too, just opens as a normal tab

## Usage

| Command | Description |
|---|---|
| `openauth` | Generate code, copy to clipboard, show notification |
| `openauth --setup` | Save your Base32 secret key |
| `openauth --print` | Print code to stdout (no clipboard, no notification) |
| `openauth --next` | Copy the *next* code (one 30s period ahead) |
| `openauth --gui` | Open the browser-based visual interface |

## Global hotkey setup

The real power is binding `openauth` to a keyboard shortcut so you can copy a 2FA code from any app without switching windows.

### macOS (Shortcuts app — no extra software)

1. Open **Shortcuts.app**
2. Create a new shortcut
3. Add a **Run Shell Script** action
4. Set the command to the full path (find it with `which openauth`):
   ```
   /path/to/openauth
   ```
5. Click the shortcut name at the top → click **ⓘ** (info) → **Add Keyboard Shortcut**
6. Press your desired key combo (e.g. `Ctrl+Shift+O`)

Now from any app: press your hotkey, then `Cmd+V` to paste.

### Windows (AutoHotkey)

Install [AutoHotkey](https://www.autohotkey.com/), then create a script:

```autohotkey
^+o::  ; Ctrl+Shift+O
Run, openauth, , Hide
return
```

### Linux (GNOME / KDE / etc.)

Add a custom keyboard shortcut in your desktop environment's settings:

- **Command:** `openauth`
- **Shortcut:** your choice (e.g. `Ctrl+Shift+O`)

## GUI mode

```bash
openauth --gui
```

Opens a small browser-based interface showing the live code with a countdown. Keyboard shortcuts work when the window is focused:

| Key | Action |
|---|---|
| `C` or `Cmd/Ctrl+C` | Copy code to clipboard |
| `N` | Toggle next code |
| `Esc` | Back to settings |
| Double-click code | Copy to clipboard |

Chrome/Chromium opens this as a standalone window (no tabs or URL bar). Other browsers open it as a regular tab — functionally identical.

## How it works

Standard TOTP ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)):
- HMAC-SHA1 with a 30-second time step
- 6-digit codes
- Base32-encoded secret key
- Compatible with Google Authenticator, Duo, 1Password, and any TOTP-based 2FA

## Where the secret is stored

**CLI mode:** `~/.config/openauth/secret` with `chmod 600` permissions. This is a plain file — similar to how `~/.ssh/` stores keys. Protect your machine, and the secret is safe.

**GUI mode:** Encrypted with AES-256-GCM in the browser's localStorage. The decryption key is a non-extractable CryptoKey in IndexedDB (cannot be exported via JavaScript). The secret is never stored in plaintext in the browser.

## Attribution

This codebase was largely vibecoded using Claude Code with Opus 4.6

## Other

If you are using this for the Harvard FAS cluster. Visit this site to request your setup token: [https://docs.rc.fas.harvard.edu/kb/openauth/](https://docs.rc.fas.harvard.edu/kb/openauth/).

## License

MIT
