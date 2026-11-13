"""Approved, device-bound third-party app removal and APK restore (Python 3.8+)."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

# Support the skill's isolated-mode invocation (`python -I /path/to/remove.py`).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from adbtools import Phone as BasePhone


PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
POLICY_ADVICE = ("Turn off the app in Settings → Security and privacy → Other security "
                 "settings → Device admin apps, then rerun the approved removal.")


class SafetyError(Exception):
    pass


class Phone(BasePhone):
    """Keep adbtools' discovery/serial handling, but check status and bound waits."""

    def raw(self, *args):
        result = subprocess.run(self._cmd(args), capture_output=True, timeout=120)
        if result.returncode:
            detail = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
            raise SafetyError(detail or "adb failed (exit {}).".format(result.returncode))
        return result.stdout


def adb(phone, *args):
    # Each argument is separate; never invoke a host shell or pass shell command strings.
    return phone.raw(*args).decode("utf-8", errors="replace").strip()


def shell(phone, *args):
    return adb(phone, "shell", *args)


def log(job, serial, package, action, result):
    entry = dict(timestamp=datetime.now(timezone.utc).isoformat(), serial=serial,
                 package=package, action=action, result=result)
    with (job / "actions.log").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=True) + "\n")


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bind(phone, job):
    if adb(phone, "get-state") != "device":
        raise SafetyError("Phone is not ready; check USB debugging and authorization.")
    identity = dict(serial=adb(phone, "get-serialno"),
                    model=shell(phone, "getprop", "ro.product.model"),
                    android_id=shell(phone, "settings", "get", "secure", "android_id"))
    if (identity["serial"] != phone.serial or
            any(not value or value.lower() in ("null", "unknown") for value in identity.values()) or
            not re.fullmatch(r"[0-9a-fA-F]+", identity["android_id"])):
        raise SafetyError("Cannot reliably identify this phone; no changes made.")
    path = job / "device.json"
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != identity:
            raise SafetyError("Device mismatch: this job belongs to a different phone. No further changes allowed.")
    else:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(identity, stream, indent=2)


def packages(phone, third_party=False):
    args = ["pm", "list", "packages"] + (["-3"] if third_party else [])
    output = shell(phone, *args)
    found = set()
    for line in output.splitlines():
        if not line.startswith("package:") or not PACKAGE.fullmatch(line[8:]):
            raise SafetyError("Could not read the installed package list: " + line)
        found.add(line[8:])
    return found


def details(phone, package):
    try:
        dump = shell(phone, "dumpsys", "package", package)
    except (SafetyError, OSError, subprocess.TimeoutExpired) as exc:
        return "label unavailable; install source unavailable; version unavailable ({})".format(exc)
    def field(pattern):
        match = re.search(pattern, dump, re.MULTILINE)
        return match.group(1).strip() if match else "unavailable"
    return "label: {}; install source: {}; version: {} (code {})".format(
        field(r"^\s*(?:application-label|nonLocalizedLabel|label)[:=]\s*([^\r\n]+)"),
        field(r"\b(?:installerPackageName|initiatingPackageName)=([^\s]+)"),
        field(r"\bversionName=([^\r\n]+)"), field(r"\bversionCode=(\d+)"))


def backup(phone, job, package):
    output = shell(phone, "pm", "path", package)
    paths = []
    for line in output.splitlines():
        if not re.fullmatch(r"package:/[A-Za-z0-9_./+=@~%-]+\.apk", line):
            raise SafetyError("Invalid APK path: " + line)
        paths.append(line[8:])
    if not paths or len(set(paths)) != len(paths):
        raise SafetyError("No complete APK path list available.")
    destination = job / "backup" / package
    destination.mkdir(parents=True, exist_ok=True)
    # Preserve previous complete backups and publish a manifest only after every pull succeeds.
    with tempfile.TemporaryDirectory(prefix="apk-", dir=str(destination)) as temporary:
        staging = Path(temporary)
        files = []
        for index, source in enumerate(paths):
            target = staging / ("{:03d}.apk".format(index))
            adb(phone, "pull", source, str(target))
            if not target.is_file() or target.stat().st_size == 0:
                raise SafetyError("APK pull produced no file: " + source)
            files.append(dict(file=target.name, source=source,
                              sha256=checksum(target)))
        # A unique generation avoids mixing old and new splits after an interrupted backup.
        generation = Path(tempfile.mkdtemp(prefix="set-", dir=str(destination)))
        for item in files:
            (staging / item["file"]).replace(generation / item["file"])
            item["file"] = generation.name + "/" + item["file"]
        manifest = destination / "manifest.tmp"
        manifest.write_text(json.dumps(dict(package=package, files=files), indent=2), encoding="utf-8")
        manifest.replace(destination / "manifest.json")
    return "Saved {} APK(s) in {}".format(len(files), destination)


def restore_files(job, package):
    folder = job / "backup" / package
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or manifest.get("package") != package or
            not isinstance(manifest.get("files"), list) or not manifest["files"]):
        raise SafetyError("Backup manifest is empty or belongs to a different package.")
    paths = []
    for item in manifest["files"]:
        path = (folder / item["file"]).resolve()
        if folder.resolve() not in path.parents or path.suffix != ".apk":
            raise SafetyError("Invalid backup file path.")
        if checksum(path) != item["sha256"]:
            raise SafetyError("Backup checksum mismatch: " + str(path))
        paths.append(str(path))
    return paths


def run(args):
    job = Path(args.job)
    job.mkdir(parents=True, exist_ok=True)
    action = "restore" if args.restore else "enable" if args.enable else "disable" if args.disable else "uninstall"
    phone = Phone(serial=args.serial)
    try:
        bind(phone, job)
        installed, third = packages(phone), packages(phone, True)
        if action == "uninstall":
            print("Plan: uninstall the packages below after backing up every APK split. "
                  "Uninstall can delete app data, accounts and settings; APK restore cannot recover them.")
        elif action == "restore":
            print("Plan: reinstall the backed-up APKs below; deleted app data cannot be recovered.")
        else:
            print("Plan: {} the packages below for user 0.".format(action))
        plans = {}
        # Validate the entire list before any app is changed.
        for package in args.packages:
            if action == "restore":
                if package in installed and package not in third:
                    raise SafetyError(package + ": refusing to overwrite a system/preinstalled app.")
                plans[package] = restore_files(job, package)
            elif package not in installed or package not in third:
                raise SafetyError(package + ": not installed or not a third-party app; refusing the entire list.")
            print("{}: {} — {}".format(action, package, details(phone, package)))
            if action == "restore":
                print("  Backup APKs: " + ", ".join(plans[package]))
        if args.no_backup:
            print("WARNING: --no-backup allows removal without a complete APK backup.")
        if not args.approved:
            for package in args.packages:
                log(job, args.serial, package, action, "dry-run: approval required")
            print("Dry run only. Show this exact plan to the tech; rerun with --approved only after a yes.")
            return 1
        failed = False
        for package in args.packages:
            try:
                bind(phone, job)
                # Open the audit trail before making changes; a log failure must stop the run.
                log(job, args.serial, package, action, "started")
                if action == "uninstall":
                    try:
                        message = backup(phone, job, package)
                    except (SafetyError, OSError, subprocess.TimeoutExpired) as exc:
                        message = "Backup failed: " + str(exc)
                        log(job, args.serial, package, "backup", message)
                        print(package + ": " + message)
                        if not args.no_backup:
                            raise SafetyError("Removal stopped because backup failed.")
                    else:
                        log(job, args.serial, package, "backup", message)
                        print(package + ": " + message)
                bind(phone, job)
                if action != "restore" and package not in packages(phone, True):
                    raise SafetyError("App is no longer installed as third-party; refusing.")
                if action == "restore":
                    if package in packages(phone) and package not in packages(phone, True):
                        raise SafetyError("Refusing to overwrite a system/preinstalled app.")
                    result = adb(phone, "install-multiple", "-r", *restore_files(job, package))
                elif action == "uninstall":
                    result = adb(phone, "uninstall", package)
                else:
                    result = shell(phone, "pm", "disable-user" if action == "disable" else "enable",
                                   "--user", "0", package)
                if action in ("disable", "enable"):
                    expected = "disabled-user" if action == "disable" else "enabled"
                    success = "new state: " + expected in result
                else:
                    success = any(line.strip() == "Success" for line in result.splitlines())
                if not success:
                    raise SafetyError(result or "adb returned no success confirmation.")
                log(job, args.serial, package, action, "success: " + result)
                print(package + ": success: " + result)
            except (SafetyError, OSError, subprocess.TimeoutExpired) as exc:
                failed = True
                message = str(exc)
                if "DELETE_FAILED_DEVICE_POLICY_MANAGER" in message:
                    message += " " + POLICY_ADVICE
                log(job, args.serial, package, action, "failed: " + message)
                print(package + ": FAILED: " + message)
        bind(phone, job)
        remaining = packages(phone, True)
        print("Third-party packages after verification:\n" + "\n".join(sorted(remaining)))
        for package in args.packages:
            if action in ("uninstall", "restore"):
                ok = (package in remaining) == (action == "restore")
                log(job, args.serial, package, "verify", "success" if ok else "failed")
                if not ok:
                    failed = True
                    print(package + ": FAILED final verification.")
        return 1 if failed else 0
    except (SafetyError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        for package in args.packages:
            log(job, args.serial, package, action, "refused: " + str(exc))
        print("Refused: " + str(exc), file=sys.stderr)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="exact adb serial; never auto-selected")
    parser.add_argument("--job", required=True, help="job folder holding device identity, backups and audit log")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--disable", action="store_true", help="disable for user 0 instead of uninstalling")
    mode.add_argument("--enable", action="store_true", help="undo --disable for user 0")
    mode.add_argument("--restore", action="store_true", help="reinstall APKs from the job's backup")
    parser.add_argument("--approved", action="store_true", help="tech approved exactly this plan in chat")
    parser.add_argument("--no-backup", action="store_true", help="allow uninstall even if APK backup fails")
    parser.add_argument("packages", nargs="+", help="exact package names")
    args = parser.parse_args(argv)
    if not args.serial.strip() or args.serial.startswith("-"):
        parser.error("--serial must be a nonempty adb serial")
    if any(not PACKAGE.fullmatch(package) for package in args.packages):
        parser.error("invalid package name; use dot-separated letters, digits and underscores")
    if len(set(args.packages)) != len(args.packages):
        parser.error("duplicate package names")
    if args.no_backup and (args.disable or args.enable or args.restore):
        parser.error("--no-backup is only valid for uninstall")
    try:
        return run(args)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print("Stopped: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
