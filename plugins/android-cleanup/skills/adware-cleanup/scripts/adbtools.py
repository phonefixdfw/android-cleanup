"""Shared helpers: find adb on Windows, macOS or Linux and run it against one phone."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Windows consoles default to a legacy code page; never crash on an odd app label.
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(errors="replace")
    except AttributeError:
        pass


def find_adb():
    """Return the adb executable, checking PATH first and then the usual install folders."""
    if os.environ.get("ADB") and Path(os.environ["ADB"]).is_file():
        return os.environ["ADB"]
    found = shutil.which("adb")
    if found:
        return found
    home = Path.home()
    exe = "adb.exe" if os.name == "nt" else "adb"
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local")) / "Android/Sdk/platform-tools",
        Path("C:/platform-tools"),
        Path("C:/Android/platform-tools"),
        home / "platform-tools",
        home / "Downloads/platform-tools",
        home / "Library/Android/sdk/platform-tools",
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    ]
    for folder in candidates:
        if (folder / exe).is_file():
            return str(folder / exe)
    sys.exit("adb not found. Install Android platform-tools "
             "(https://developer.android.com/tools/releases/platform-tools), "
             "or set the ADB environment variable to the full path of adb.")


class Phone:
    def __init__(self, serial=None):
        self.adb = find_adb()
        self.serial = serial

    def _cmd(self, args):
        return [self.adb] + (["-s", self.serial] if self.serial else []) + list(args)

    def raw(self, *args, timeout=60):
        """Run an adb command and return its stdout as bytes. adb errors are shown, never swallowed."""
        try:
            r = subprocess.run(self._cmd(args), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            sys.exit(f"adb timed out after {timeout}s; phone disconnected or adb failed, re-run.")
        self.last_returncode = r.returncode
        self.last_error = r.stderr.decode("utf-8", errors="replace").strip()
        if r.returncode != 0:
            print(f"adb error (exit {r.returncode}): {self.last_error or 'no error details'}", file=sys.stderr)
        return r.stdout

    def require_connected(self):
        """Stop with a plain explanation unless exactly this phone is connected and authorized."""
        state = self.raw("get-state").decode("utf-8", errors="replace").strip()
        if state == "device":
            return
        err = self.last_error
        if "unauthorized" in err:
            sys.exit("Phone is unauthorized: unlock it and tap Allow on the 'Allow USB debugging?' prompt.")
        if "no permissions" in err or "insufficient permissions" in err:
            sys.exit("Linux USB permission problem: install your distro's adb udev rules "
                     "(Debian/Ubuntu: adb; Arch: android-udev), unplug and replug the phone, and try again.")
        if "more than one" in err:
            sys.exit("More than one phone connected: pass --serial (see `adb devices`).")
        sys.exit(f"Phone not ready ({state or err or 'not found'}). Check USB debugging is on and the cable carries data.")

    def shell(self, command, timeout=60):
        """Run one shell command string on the phone and return its text output."""
        output = self.raw("shell", command, timeout=timeout).decode("utf-8", errors="replace").replace("\r\n", "\n")
        if self.last_returncode:
            # Preserve the failure for analysis, including errors printed only on stderr.
            output += f"\nadb command failed (exit {self.last_returncode}): {self.last_error}"
        return output


def add_serial_arg(parser):
    parser.add_argument("--serial", "-s", help="phone serial from `adb devices` (needed if more than one is connected)")


if __name__ == "__main__":
    print(find_adb())  # full path to adb, for running adb commands directly
