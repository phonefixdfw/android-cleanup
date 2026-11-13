"""Read-only adware triage for an adb-connected Android phone. Changes nothing on the device.
Usage: python triage.py --serial <serial> <out-dir>
Writes raw dumps to <out-dir> and prints a summary.
"""
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # -I drops the script folder
from adbtools import Phone, add_serial_arg
import usage_events


def packages_newest_first(dump, listing):
    """Rows of (first install, last update, installer, package) for third-party apps, newest first."""
    installer = {}
    for line in listing.splitlines():
        m = re.match(r"package:(\S+)\s+installer=(\S+)", line.strip())
        if m:
            installer[m.group(1)] = m.group(2)
    info, cur = {}, None
    for line in dump.splitlines():
        m = re.match(r"\s*Package \[([^\]]+)\]", line)
        if m:
            cur = m.group(1)
            info.setdefault(cur, {})
            continue
        if cur:
            for key in ("firstInstallTime", "lastUpdateTime"):
                m = re.search(key + r"=(\S+ \S+)", line)
                if m and key not in info[cur]:
                    info[cur][key] = m.group(1)
    rows = [(info.get(p, {}).get("firstInstallTime", "?"), info.get(p, {}).get("lastUpdateTime", "?"), inst, p)
            for p, inst in installer.items()]
    return sorted(rows, key=lambda r: (r[0] != "?", r[0]), reverse=True)


# Installers whose apps count as coming from a store. Anything else (no installer, the system
# package installer, a browser, a messenger, a file manager) means the APK was sideloaded.
STORES = {"com.android.vending": "Play Store", "com.sec.android.app.samsungapps": "Galaxy Store",
          "com.amazon.venezia": "Amazon Appstore", "com.huawei.appmarket": "AppGallery"}
TRANSFER = {"com.sec.android.easyMover": "Smart Switch transfer", "com.google.android.apps.restore": "Google restore"}
CARRIER = re.compile(r"^com\.(dti|att|tmobile|verizon|vzw|sprint|uscellular|motricity|ironsrc\.aura)\b")
JUNK_NAME = re.compile(r"clean|boost|junk|cooler|antivirus|virus|shield|guard|battery|flashlight|torch|"
                       r"applock|qrcode|qrscan|wallpaper|weather|launcher|optimi[sz]|speed|phonemaster|"
                       r"vpn|antispy|phonecare|ramclean|cpucool", re.I)
BROWSERS = {"com.android.chrome": "Chrome", "com.sec.android.app.sbrowser": "Samsung Internet",
            "org.mozilla.firefox": "Firefox", "org.mozilla.firefox_beta": "Firefox Beta",
            "org.mozilla.focus": "Firefox Focus", "com.microsoft.emmx": "Edge", "com.brave.browser": "Brave",
            "com.opera.browser": "Opera", "com.opera.mini.native": "Opera Mini", "com.opera.gx": "Opera GX",
            "com.duckduckgo.mobile.android": "DuckDuckGo", "com.vivaldi.browser": "Vivaldi",
            "com.kiwibrowser.browser": "Kiwi", "com.UCMobile.intl": "UC Browser", "mark.via.gp": "Via",
            "com.chrome.beta": "Chrome Beta", "com.google.android.googlequicksearchbox": None}
PKG = r"[a-zA-Z][\w]*(?:\.[\w]+)+"


def install_source(installer):
    """(label, sideloaded?) for an installer package name."""
    if installer in STORES:
        return STORES[installer], False
    if installer in TRANSFER:
        return TRANSFER[installer], False
    if CARRIER.match(installer or ""):
        return "carrier preload", False
    if installer in ("null", "", None):
        return "SIDELOADED (no installer)", True
    return f"SIDELOADED via {installer}", True


def package_details(dump):
    """Per package: firstInstallTime, lastUpdateTime, and granted permission names."""
    info, cur = {}, None
    for line in dump.splitlines():
        m = re.match(r"\s*Package \[([^\]]+)\]", line)
        if m:
            cur = m.group(1)
            info.setdefault(cur, {"perms": set()})
            continue
        if not cur:
            continue
        for key in ("firstInstallTime", "lastUpdateTime"):
            m = re.search(key + r"=(\S+ \S+)", line)
            if m and key not in info[cur]:
                info[cur][key] = m.group(1)
        m = re.match(r"\s*([\w.]+): granted=true", line)
        if m:
            info[cur]["perms"].add(m.group(1))
    return info


def app_usage(usage):
    """Per package: (latest lastTimeUsed, highest appLaunchCount) across all usage-stats intervals."""
    out = {}
    for m in re.finditer(r'package=(\S+) totalTimeUsed="[^"]*" lastTimeUsed="([^"]+)"(.*)', usage):
        pkg, last, rest = m.group(1), m.group(2), m.group(3)
        launch_match = re.search(r"appLaunchCount=(\d+)", rest)
        launches = int(launch_match.group(1)) if launch_match else 0
        prev_last, prev_launch = out.get(pkg, ("", 0))
        out[pkg] = (max(prev_last, last if not last.startswith("19") else ""), max(prev_launch, launches))
    return out


def packages_in(text):
    return set(re.findall(PKG + r"(?=/|:|\s|$)", text or ""))


def suspect_apps(dump, listing, usage, today, access, launcher_pkgs):
    """Third-party apps scored on adware red flags, highest first: (score, package, source, reasons).
    access maps a label ("draws over other apps", ...) to the set of packages holding that access."""
    details, used = package_details(dump), app_usage(usage)
    rows = []
    for line in listing.splitlines():
        m = re.match(r"package:(\S+)\s+installer=(\S+)", line.strip())
        if not m:
            continue
        pkg, installer = m.groups()
        source, sideloaded = install_source(installer)
        d = details.get(pkg, {"perms": set()})
        first = (d.get("firstInstallTime") or "")[:10]
        if sideloaded and ((first and first[:4] < "2010") or pkg.startswith(("com.samsung.", "com.sec."))):
            source, sideloaded = "factory preinstalled", False  # factory image apps carry a 2008/2009 stamp
        score, why = 0, []
        if pkg.startswith("org.chromium.webapk."):
            score += 2
            why.append("a website installed as an app (WebAPK): find which site in its app info")
        if sideloaded:
            score += 4
            why.append("not from an app store (sideloaded, patched or cracked apps land here)")
        for label, pkgs in access.items():
            if pkg in pkgs:
                weight = 3 if label in ("device admin", "accessibility service") else 1
                score += weight
                why.append(label)
        if launcher_pkgs and pkg not in launcher_pkgs:
            score += 2
            why.append("no app icon (hidden from the app drawer)")
        last_update = (d.get("lastUpdateTime") or "")[:10]
        last_used, launches = used.get(pkg, ("", 0))
        try:
            age = (today - dt.date.fromisoformat(first)).days
        except ValueError:
            age = None
        if age is not None and age > 3 and not last_used and launches == 0:
            score += 1
            why.append("never opened in the usage history")
        if age is not None and age <= 30:
            score += 1
            why.append(f"installed {first}")
        try:
            if (today - dt.date.fromisoformat(last_update)).days > 730:
                score += 1
                why.append(f"not updated since {last_update} (abandoned)")
        except ValueError:
            pass
        if JUNK_NAME.search(pkg):
            score += 1
            why.append("cleaner/booster/VPN-type utility name (a common adware disguise)")
        if "android.permission.REQUEST_INSTALL_PACKAGES" in d["perms"] or pkg in access.get("_install", set()):
            score += 1
            why.append("can install other apps")
        rows.append((score, pkg, source, [w for w in why]))
    rows.sort(key=lambda r: (-r[0], r[1]))
    return rows


def site_channels(notif):
    """Browser site-notification channels as (date granted, site), newest first."""
    found = set(re.findall(r"mId='web:https?://([^;']*);(\d+)'", notif))
    rows = []
    for host, stamp in found:
        # Chrome stores the grant time as microseconds since 1601-01-01 (Windows FILETIME epoch).
        try:
            when = dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=int(stamp))
        except (ValueError, OverflowError):
            continue
        rows.append((when.strftime("%Y-%m-%d"), host))
    return sorted(rows, reverse=True)


# Stable names are also fixture filenames and the collect() API keys.
COMMANDS = {
    "device": 'echo "$(getprop ro.product.model) | Android $(getprop ro.build.version.release) | '
              '$(getprop ro.build.display.id)"; date',
    "packages": "dumpsys package packages",
    "notif": "dumpsys notification",  # default redaction retains channel IDs (AOSP NotificationChannel.dump)
    "usage": "dumpsys usagestats",
    "third-party": "pm list packages -3 -i",
    "overlays": "appops query-op SYSTEM_ALERT_WINDOW allow",
    "admins": "dumpsys device_policy",
    "accessibility": "settings get secure enabled_accessibility_services",
    "listeners": "settings get secure enabled_notification_listeners",
    "home_role": "cmd role get-role-holders android.app.role.HOME",
    "browser_role": "cmd role get-role-holders android.app.role.BROWSER",
    "installers": "appops query-op REQUEST_INSTALL_PACKAGES allow",
    "launcher": "cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER",
    "date": "date +%F",
    "browsing": "cmd package query-activities --brief -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d http://example.com",
    "installed": "pm list packages",
}
ERROR = re.compile(r"(?im)^\s*(?:error\b|usage:|unknown (?:command|operation|option)|"
                   r"(?:AppOps service|Role manager|Package manager).*commands:|Available commands:|"
                   r"unsupported\b|not supported\b|(?:cmd: )?can't find service|cannot find service|"
                   r"exception\b|java\.\w*exception|securityexception|permission denial|"
                   r"adb:|adb command failed|.*: (?:not found|inaccessible or not found))")
CHECKS = {"overlays": "draws over other apps", "admins": "device admin",
          "accessibility": "accessibility service", "listeners": "reads notifications",
          "home_role": "default home", "browser_role": "default browser",
          "installers": "install other apps", "launcher": "hidden app icons",
          "browsing": "browser activity discovery", "installed": "installed browsers"}


def collect(phone):
    """Collect read-only outputs; no files or printing. Longer limits for large dumps."""
    return {name: phone.shell(command, timeout=180 if name in ("packages", "usage") else 60)
            for name, command in COMMANDS.items()}


def analyze(raw, today):
    """Validate core dumps and return a JSON-serializable summary, without I/O."""
    markers = {"packages": r"Package \[", "third-party": r"(?m)^package:",
               "usage": r"(?i)(?:UsageStats|Usage stats|In-memory (?:daily|weekly)|time range|timeRange|package=|Events:)",
               "notif": r"(?i)(?:Notification service|Notification Manager|Notification List|NotificationChannel|PackagePreferences)"}
    for name, marker in markers.items():
        text = raw.get(name, "")
        if not text.strip() or ERROR.search(text) or not re.search(marker, text):
            raise ValueError(f"{name}.txt is empty or malformed: phone disconnected or adb failed, re-run.")
    skipped = []
    values = {}
    for name, label in CHECKS.items():
        text = raw.get(name)
        # Empty output is legitimate for access lists and role holders.
        if (text is None or ERROR.search(text)
                or (name in ("admins", "installed", "accessibility", "listeners") and not text.strip())
                or (name == "installed" and not re.search(r"(?m)^package:", text))):
            skipped.append(f"{label}: command failed or unsupported on this Android version")
            values[name] = ""
        else:
            values[name] = text.strip()
    launcher = packages_in(values["launcher"])
    if len(launcher) < 5:
        launcher = set()
        if not any(s.startswith("hidden app icons:") for s in skipped):
            skipped.append("hidden app icons: launcher listing incomplete (fewer than 5 packages)")
    admins = sorted(set(re.findall(r"ComponentInfo\{[^}]+\}", values["admins"])))
    access = {"draws over other apps": packages_in(values["overlays"]),
              "device admin": packages_in(" ".join(admins)),
              "accessibility service": packages_in(values["accessibility"]),
              "reads notifications": packages_in(values["listeners"]),
              "_install": packages_in(values["installers"])}
    rows = suspect_apps(raw["packages"], raw["third-party"], raw["usage"], today, access, launcher)
    installed = set(re.findall(r"package:(\S+)", values["installed"]))
    browsers = [{"package": p, "name": BROWSERS.get(p, p)} for p in sorted(
        (set(BROWSERS) & installed) | (packages_in(values["browsing"]) & {r[1] for r in rows}))
        if BROWSERS.get(p, p) is not None]
    device = raw.get("device", "").strip()
    parts = device.splitlines()[0].split(" | ") if device else []
    if len(parts) < 2 or ERROR.search(device):
        skipped.append("device information: command failed or malformed")
    days = [str(today - dt.timedelta(d)) for d in range(2)]
    return {"device": {"model": parts[0] if parts else "?",
                       "android_version": (parts[1][8:] if len(parts) > 1 and parts[1].startswith("Android ") else "?"),
                       "summary": device},
            "packages": packages_newest_first(raw["packages"], raw["third-party"]),
            "suspects": [{"score": r[0], "package": r[1], "source": r[2], "reasons": r[3]} for r in rows],
            "browsers": browsers, "site_channels": site_channels(raw["notif"]),
            "access": {k: sorted(v) for k, v in access.items()},
            "access_display": {"overlays": values["overlays"], "admins": "\n".join(admins),
                               "accessibility": values["accessibility"], "listeners": values["listeners"].replace(":", "\n"),
                               "roles": "\n".join(filter(None, (values["home_role"], values["browser_role"])))},
            "usage_events": usage_events.interesting(usage_events.parse_events(raw["usage"].splitlines(), days)),
            "skipped_checks": skipped}


def print_summary(result, out, show_all=False):
    print("== DEVICE")
    print(result["device"]["summary"])
    print(f"== RAW DUMPS -> {out}")
    print("== THIRD-PARTY APPS, NEWEST FIRST (install date | last update | installer | package)")
    for first, last, inst, pkg in result["packages"][:40]:
        print(f"{first[:16]} | {last[:16]} | {inst} | {pkg}")
    if len(result["packages"]) > 40:
        print(f"   ...{len(result['packages']) - 40} more. Full list: {out / 'third-party.txt'}")
    for key, title in (("overlays", "DRAW OVER OTHER APPS (SYSTEM_ALERT_WINDOW allowed)"),
                       ("admins", "DEVICE ADMINS"), ("accessibility", "ACCESSIBILITY SERVICES"),
                       ("listeners", "NOTIFICATION LISTENERS"), ("roles", "DEFAULT HOME / BROWSER")):
        print("== " + title)
        print(result["access_display"][key])
    print("== SUSPECT APPS, MOST SUSPICIOUS FIRST (score | package | install source | red flags)")
    print("   Sideloaded apps are top suspects: recommend removing every one the customer can't vouch for.")
    print("   Store, carrier and Smart Switch apps are trusted sources, but still check the flags.")
    rows = result["suspects"]
    for r in rows:
        if r["score"] >= 3 or show_all:
            print(f"{r['score']:>2} | {r['package']} | {r['source']} | {'; '.join(r['reasons'])}")
    print(f"   {sum(r['source'].startswith('SIDELOADED') for r in rows)} sideloaded app(s); "
          f"{sum(r['score'] < 3 for r in rows)} other app(s) scored below 3 "
          "(weak or no red flags; full scores: rerun with --all).")
    print("== BROWSERS INSTALLED (clear site notifications in every one)")
    for b in result["browsers"]:
        print(f"{b['name']} ({b['package']})")
    print("== BROWSER SITE NOTIFICATION CHANNELS, NEWEST FIRST (date granted | site)")
    print("   Chrome-based browsers only. Android keeps a channel after the site is blocked, so confirm in the browser.")
    for day, host in result["site_channels"]:
        print(day, host)
    print("== USAGE EVENTS (last 2 days): ad screens, browser launches, suspects")
    for e in result["usage_events"]:
        print(" ".join(e))
    print("== CHECKS SKIPPED")
    print("\n".join(result["skipped_checks"]) or "None")


def main():
    ap = argparse.ArgumentParser()
    add_serial_arg(ap)
    ap.add_argument("out")
    ap.add_argument("--all", action="store_true", help="list every third-party app with its score")
    ap.add_argument("--json", metavar="FILE", help="write the structured summary as JSON")
    a = ap.parse_args()
    phone = Phone(a.serial)
    phone.require_connected()
    raw = collect(phone)
    try:
        today = dt.date.fromisoformat(raw["date"].strip())
    except ValueError:
        today = dt.date.today()
    try:
        result = analyze(raw, today)
    except ValueError as exc:
        sys.exit(str(exc))
    if raw["date"].strip() != str(today):
        result["skipped_checks"].append("phone date: unavailable; usage window uses computer date")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for name in ("packages", "notif", "usage", "third-party"):
        (out / (name + ".txt")).write_text(raw[name], encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print_summary(result, out, a.all)


if __name__ == "__main__":
    main()
