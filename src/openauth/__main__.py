"""
OpenAuth TOTP — generate 2FA codes and copy to clipboard.

Implements the TOTP (Time-based One-Time Password) algorithm per RFC 6238.
This is the same algorithm used by Google Authenticator, Duo, 1Password, and
Harvard's OpenAuth system. The secret key is a shared secret between the
server and client, encoded in Base32. Every 30 seconds, the current Unix time
is divided by 30 to produce a counter, which is HMAC-SHA1'd with the secret
to produce a 6-digit code.

Usage:
    openauth              Generate current code and copy to clipboard
    openauth --setup      Save your Base32 secret key
    openauth --print      Print code to stdout instead of copying
    openauth --next       Show next code (one period ahead)
    openauth --gui        Open the browser-based GUI

Dependencies: None (Python 3.10+ standard library only).

Clipboard tools (pre-installed on macOS and Windows):
    macOS:   pbcopy
    Windows: clip
    Linux:   xclip or xsel (install via package manager)
"""

## typing
from __future__ import annotations

## built-ins
import argparse
import hashlib
import hmac
import os
import platform
import shutil
import struct
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


# =============================================================================
# Configuration
# =============================================================================

## The secret is stored as a plaintext file with chmod 600 (owner-read-only),
## similar to how ~/.ssh/id_rsa is stored. This is adequate for a TOTP shared
## secret — the same secret also lives on the server.
CONFIG_DIR = Path.home() / ".config" / "openauth"
FILEPATH_SECRET = CONFIG_DIR / "secret"

## The HTML file is bundled alongside this module via setuptools package-data.
## It contains a self-contained TOTP GUI (vanilla JS, no build step).
FILEPATH_HTML = Path(__file__).parent / "openauth.html"


# =============================================================================
# TOTP Core
# =============================================================================


def base32_decode(s_encoded: str) -> bytes:
    """
    Decode a Base32-encoded string into raw bytes.

    Base32 encodes arbitrary bytes using the 32-character alphabet A-Z plus
    2-7. Each character represents 5 bits. Characters are consumed
    left-to-right, accumulating bits into a buffer. Every time 8+ bits are
    available, one byte is emitted.

    This is a from-scratch implementation to avoid depending on the ``base64``
    module's quirks around padding. TOTP secrets are commonly provided without
    padding (``=``), with spaces, or with hyphens — all of which we strip.

    Args:
        s_encoded (str):
            A Base32-encoded string. Case-insensitive. Spaces, hyphens, and
            trailing ``=`` padding are stripped automatically.

    Returns:
        (bytes):
            decoded_bytes (bytes):
                The decoded raw bytes. For a typical TOTP secret, this is a
                10-20 byte HMAC key.

    Raises:
        ValueError:
            If any character (after cleaning) is not in the Base32 alphabet.

    Example:
        .. code-block:: python

            key_bytes = base32_decode("JBSWY3DPEHPK3PXP")
    """
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    s_clean = s_encoded.upper().replace(" ", "").replace("-", "").rstrip("=")
    lookup = {char: idx for idx, char in enumerate(ALPHABET)}

    n_bits = 0  # how many bits are currently in the accumulator
    accumulator = 0  # bit buffer; grows from the right as we shift in 5-bit chunks
    output = bytearray()

    for char in s_clean:
        if char not in lookup:
            raise ValueError(
                f"Invalid base32 character: '{char}'. "
                f"Valid characters are A-Z and 2-7."
            )
        ## Shift accumulator left by 5 and OR-in the new 5-bit value.
        ## Example: if accumulator is 0b110 (3 bits) and we add 'C' (=2=0b00010),
        ## result is 0b110_00010 (8 bits), so we can emit one byte.
        accumulator = (accumulator << 5) | lookup[char]
        n_bits += 5

        if n_bits >= 8:
            ## Extract the top 8 bits as one byte
            n_bits -= 8
            output.append((accumulator >> n_bits) & 0xFF)

    return bytes(output)


def generate_totp(
    secret: str,
    time_step: int = 30,
    n_digits: int = 6,
    offset_steps: int = 0,
) -> str:
    """
    Generate a TOTP code per RFC 6238.

    The algorithm:
        1. Divide the current Unix timestamp by ``time_step`` (30s) to get a
           counter value. This means the counter increments once every 30s,
           and all devices with the same secret + clock produce the same
           counter.
        2. Encode the counter as an 8-byte big-endian integer.
        3. Compute HMAC-SHA1(secret_bytes, counter_bytes) -> 20-byte hash.
        4. "Dynamic truncation": use the low 4 bits of the last hash byte as
           an offset index into the hash. Extract 4 bytes starting at that
           offset, mask off the top bit (to ensure a positive 31-bit integer).
        5. Take that integer mod 10^n_digits to get the final code.

    Reference: https://datatracker.ietf.org/doc/html/rfc6238

    Args:
        secret (str):
            Base32-encoded shared secret key (e.g. "JBSWY3DPEHPK3PXP").
        time_step (int):
            Duration of each TOTP period in seconds. Standard is 30.
        n_digits (int):
            Number of digits in the output code. Standard is 6.
        offset_steps (int):
            Number of time steps to offset from now. 0 = current code,
            1 = next code, -1 = previous code.

    Returns:
        (str):
            code (str):
                Zero-padded TOTP code string, e.g. "028374".
    """
    key_bytes = base32_decode(secret)

    ## Step 1: Counter = floor(unix_time / time_step) + offset
    ## This is the "T" value in RFC 6238. All devices with the same clock
    ## and secret will compute the same counter at the same moment.
    counter = int(time.time()) // time_step + offset_steps

    ## Step 2: Pack counter as 8-byte big-endian (network byte order).
    ## ">Q" format: big-endian unsigned 64-bit integer.
    counter_bytes = struct.pack(">Q", counter)

    ## Step 3: HMAC-SHA1(key, counter) -> 20-byte hash.
    ## HMAC is a keyed hash — it proves you know the secret without
    ## revealing it. SHA1 is fine here; TOTP security comes from the
    ## secret, not collision resistance.
    hash_bytes = hmac.new(
        key=key_bytes, msg=counter_bytes, digestmod=hashlib.sha1
    ).digest()  # hash_bytes: 20 bytes

    ## Step 4: Dynamic truncation (RFC 4226 Section 5.4).
    ## Take the last byte's low nibble (4 bits, value 0-15) as an offset
    ## index into the 20-byte hash. This is a clever trick that distributes
    ## the code selection across the full hash, not just the first few bytes.
    offset_idx = hash_bytes[-1] & 0x0F  # offset_idx: int in [0, 15]

    ## Read 4 bytes starting at offset_idx, mask off the sign bit (& 0x7F
    ## on the first byte) to guarantee a positive 31-bit integer.
    ## The bit manipulation below assembles 4 bytes into a big-endian int:
    ##   byte0 << 24 | byte1 << 16 | byte2 << 8 | byte3
    truncated_int = (
        (hash_bytes[offset_idx] & 0x7F) << 24
        | (hash_bytes[offset_idx + 1] & 0xFF) << 16
        | (hash_bytes[offset_idx + 2] & 0xFF) << 8
        | (hash_bytes[offset_idx + 3] & 0xFF)
    )  # truncated_int: positive 31-bit integer

    ## Step 5: Modulo to get the desired number of digits.
    ## e.g. 123456789 % 1000000 = 456789
    code_int = truncated_int % (10**n_digits)
    return str(code_int).zfill(n_digits)


# =============================================================================
# Clipboard (cross-platform)
# =============================================================================


def copy_to_clipboard(text: str) -> None:
    """
    Copy a string to the system clipboard.

    Uses the platform's native clipboard command-line tool. These are
    pre-installed on macOS (``pbcopy``) and Windows (``clip``). On Linux,
    ``xclip`` or ``xsel`` must be installed by the user.

    Args:
        text (str):
            The string to copy to the clipboard.

    Raises:
        SystemExit:
            If no clipboard tool is found (Linux only).
    """
    system = platform.system()

    if system == "Darwin":
        ## pbcopy reads from stdin and places content on the clipboard.
        subprocess.run(["pbcopy"], input=text.encode(), check=True)
    elif system == "Windows":
        ## clip.exe reads from stdin, available since Windows XP.
        subprocess.run(["clip"], input=text.encode(), check=True)
    else:
        ## Linux: try xclip first (more common), then xsel
        for cmd in [
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ]:
            if shutil.which(cmd[0]) is not None:
                subprocess.run(cmd, input=text.encode(), check=True)
                return
        print(
            "No clipboard tool found. Install xclip or xsel:\n"
            "  sudo apt install xclip",
            file=sys.stderr,
        )
        sys.exit(1)


# =============================================================================
# Secret key persistence
# =============================================================================


def save_secret(secret: str) -> None:
    """
    Validate and save a Base32 TOTP secret to ~/.config/openauth/secret.

    The file is created with 0o600 permissions (owner read/write only),
    similar to how SSH private keys are stored. On Windows, chmod is a no-op
    but NTFS ACLs typically restrict access to the owning user profile anyway.

    Args:
        secret (str):
            Base32-encoded secret key. Whitespace, hyphens, and padding are
            stripped before saving.

    Raises:
        ValueError:
            If the secret contains invalid Base32 characters.
    """
    secret_clean = (
        secret.strip().upper().replace(" ", "").replace("-", "").rstrip("=")
    )
    ## Validate by attempting decode — raises ValueError if malformed
    base32_decode(secret_clean)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    FILEPATH_SECRET.write_text(secret_clean)
    try:
        FILEPATH_SECRET.chmod(0o600)
    except OSError:
        pass  # Windows: chmod is not meaningful; NTFS ACLs handle permissions
    print(f"Secret saved to {FILEPATH_SECRET}")


def load_secret() -> str:
    """
    Load the saved TOTP secret from ~/.config/openauth/secret.

    Returns:
        (str):
            secret (str):
                The Base32-encoded secret key.

    Raises:
        SystemExit:
            If no secret file exists. Prints a message directing the user to
            run ``openauth --setup``.
    """
    if not FILEPATH_SECRET.exists():
        print("No secret saved. Run: openauth --setup", file=sys.stderr)
        sys.exit(1)
    return FILEPATH_SECRET.read_text().strip()


# =============================================================================
# Desktop notifications (cross-platform, best-effort)
# =============================================================================


def notify(title: str, message: str) -> None:
    """
    Show a desktop notification. Best-effort — silently does nothing if the
    platform's notification tool is unavailable.

    Uses:
        - macOS: ``osascript`` (AppleScript ``display notification``)
        - Windows: PowerShell UWP ToastNotification API
        - Linux: ``notify-send`` (part of libnotify)

    Args:
        title (str):
            Notification title line (e.g. "123 456").
        message (str):
            Notification body (e.g. "12s remaining").
    """
    system = platform.system()
    try:
        if system == "Darwin":
            ## osascript talks to macOS Notification Center via AppleScript.
            ## `display notification` is a built-in AppleScript command.
            subprocess.Popen([
                "osascript",
                "-e",
                f'display notification "{message}" with title "{title}"',
            ])

        elif system == "Windows":
            ## Windows 10+ toast notifications via PowerShell and the UWP
            ## ToastNotificationManager .NET class. This:
            ##   1. Loads the WinRT notification classes
            ##   2. Gets an XML template for a simple toast
            ##   3. Fills in the text node with our message
            ##   4. Shows the toast via the 'OpenAuth' app identifier
            ps_script = (
                "[Windows.UI.Notifications.ToastNotificationManager, "
                "Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
                "$xml = [Windows.UI.Notifications.ToastNotificationManager]"
                "::GetTemplateContent(0); "
                "$xml.GetElementsByTagName('text')[0].AppendChild("
                f"$xml.CreateTextNode('{title} — {message}')) > $null; "
                "[Windows.UI.Notifications.ToastNotificationManager]"
                "::CreateToastNotifier('OpenAuth').Show("
                "[Windows.UI.Notifications.ToastNotification]::new($xml))"
            )
            subprocess.Popen(["powershell", "-Command", ps_script])

        else:
            ## Linux: notify-send is part of libnotify, installed on most
            ## desktop distros. Headless servers won't have it — that's fine.
            if shutil.which("notify-send") is not None:
                subprocess.Popen([
                    "notify-send", "OpenAuth", f"{title} — {message}"
                ])
    except Exception:
        pass  # Notifications are best-effort; never block the main flow


# =============================================================================
# GUI launcher
# =============================================================================


def find_chrome() -> str | None:
    """
    Search for a Chrome or Chromium binary on the current platform.

    Chrome is preferred for ``--app`` mode, which opens the HTML file in a
    standalone window without tabs, URL bar, or bookmarks. If not found, the
    caller falls back to the system default browser.

    Returns:
        (str | None):
            filepath_chrome (str | None):
                Absolute path to the Chrome/Chromium binary, or ``None``.
    """
    system = platform.system()

    if system == "Darwin":
        ## macOS: Chrome and Chromium install to /Applications by convention.
        ## The actual binary lives inside the .app bundle at
        ## Contents/MacOS/<AppName>.
        for name_app in ["Google Chrome", "Chromium"]:
            filepath = f"/Applications/{name_app}.app/Contents/MacOS/{name_app}"
            if os.path.exists(filepath):
                return filepath

    elif system == "Windows":
        ## Windows: Chrome installs under Program Files or LocalAppData.
        for dir_base in [
            os.environ.get("PROGRAMFILES", ""),
            os.environ.get("PROGRAMFILES(X86)", ""),
            os.environ.get("LOCALAPPDATA", ""),
        ]:
            if not dir_base:
                continue
            for subpath in [
                os.path.join("Google", "Chrome", "Application", "chrome.exe"),
                os.path.join("Chromium", "Application", "chrome.exe"),
            ]:
                filepath = os.path.join(dir_base, subpath)
                if os.path.exists(filepath):
                    return filepath

    else:
        ## Linux: typically on $PATH under various names
        for name_bin in ["google-chrome", "chromium-browser", "chromium"]:
            filepath = shutil.which(name_bin)
            if filepath is not None:
                return filepath

    return None


def open_gui() -> None:
    """
    Open the TOTP GUI in a browser.

    If Chrome/Chromium is found, opens the HTML file in ``--app`` mode — a
    standalone window with no browser chrome (no tabs, no URL bar). Otherwise
    falls back to the system default browser, which opens as a normal tab.
    Functionally identical either way.
    """
    url = FILEPATH_HTML.as_uri()
    filepath_chrome = find_chrome()

    if filepath_chrome is not None:
        ## --app=<url> tells Chrome to open a frameless window for just this
        ## URL. No tabs, no URL bar, no bookmarks — just the page content.
        subprocess.Popen([filepath_chrome, f"--app={url}"])
    else:
        ## webbrowser.open() delegates to the OS-registered default browser.
        webbrowser.open(url)


# =============================================================================
# CLI entry point
# =============================================================================


def main() -> None:
    """
    CLI entry point for the ``openauth`` command.

    Dispatches to setup, gui, print, or the default copy-to-clipboard flow
    based on CLI flags. The default (no flags) generates the current TOTP
    code, copies it to the clipboard, and shows a desktop notification.
    """
    parser = argparse.ArgumentParser(
        description="OpenAuth TOTP — copy 2FA codes to clipboard",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Save your Base32 secret key to ~/.config/openauth/secret",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        dest="print_only",
        help="Print code to stdout instead of copying to clipboard",
    )
    parser.add_argument(
        "--next",
        action="store_true",
        help="Use the next code (one 30s period ahead of current)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Open the browser-based visual interface",
    )
    args = parser.parse_args()

    ## Dispatch: --gui
    if args.gui:
        open_gui()
        return

    ## Dispatch: --setup (one-time secret save)
    if args.setup:
        secret = input("Enter your Base32 secret key: ")
        save_secret(secret)
        return

    ## Default: generate code and copy to clipboard
    secret = load_secret()
    offset = 1 if args.next else 0
    code = generate_totp(secret=secret, offset_steps=offset)

    if args.print_only:
        print(code)
    else:
        copy_to_clipboard(text=code)
        n_seconds_remaining = 30 - (int(time.time()) % 30)
        notify(
            title=f"{code[:3]} {code[3:]}",
            message=f"{n_seconds_remaining}s remaining",
        )
        print(f"{code} (copied, {n_seconds_remaining}s remaining)")


if __name__ == "__main__":
    main()
