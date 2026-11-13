"""Read-only adware triage for an adb-connected Android phone. Changes nothing on the device.
Usage: python triage.py --serial <serial> <out-dir>
Writes diagnostic dumps (notification content filtered) to <out-dir> and prints a summary.
"""
import argparse
import datetime as dt
import json
import contextlib
import io
from collections import Counter
from urllib.parse import urlsplit
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # -I drops the script folder
from adbtools import Phone, add_serial_arg
import usage_events
from browsers import BROWSERS


# All scoring weights, including access checks, live here.
SCORES = {"webapk": 2, "sideload": 4, "spoof": 2, "carrier_push": 1,
          "device admin": 3, "accessibility service": 3, "reads notifications": 2,
          "draws over other apps": 1, "_install": 1, "default home": 3,
          "hidden": 2, "unused": 1, "recent": 1, "abandoned": 1,
          "utility": 1, "installer": 1, "full_screen": 2, "boot_service": 1}

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
CARRIER = re.compile(r"^com\.(att|tmobile|verizon|vzw|sprint|uscellular|motricity)\b")
PUSHERS = re.compile(r"^(?:com\.dti|(?:com\.)?ironsrc\.aura)(?:\.|$)")

JUNK_NAME = re.compile(r"clean|boost|junk|cooler|antivirus|virus|shield|guard|battery|flashlight|torch|"
                       r"applock|qrcode|qrscan|wallpaper|weather|launcher|optimi[sz]|speed|phonemaster|"
                       r"vpn|antispy|phonecare|ramclean|cpucool", re.I)
PKG = r"[a-zA-Z][\w]*(?:\.[\w]+)+"
SUBSCRIPTION_TYPE = re.compile(r"(?:^|[._-])(?:webcal|ical|ics|subscription|subscriptions|subscribed)(?:$|[._-])", re.I)


def install_source(installer):
    """(label, sideloaded?) for an installer package name."""
    if PUSHERS.match(installer or ""):
        return "pushed by carrier app installer (DT Ignite/Aura)", False
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
        m = re.search(r"codePath=(\S+)", line)
        if m:
            info[cur]["system"] = m.group(1).startswith(("/system/", "/product/", "/vendor/", "/system_ext/", "/odm/"))
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
        if sideloaded and ((first and first[:4].isdigit() and first[:4] < "2010") or d.get("system", False)):
            source, sideloaded = "factory preinstalled", False  # factory image apps carry a 2008/2009 stamp
        score, why = 0, []
        if source.startswith("pushed by"):
            score += SCORES["carrier_push"]
            why.append(source)
        if sideloaded and pkg.startswith(("com.samsung.", "com.sec.")):
            score += SCORES["spoof"]
            why.append("pretends to be a Samsung/system app")
        if pkg.startswith("org.chromium.webapk."):
            score += SCORES["webapk"]
            why.append("a website installed as an app (WebAPK): find which site in its app info")
        if sideloaded:
            score += SCORES["sideload"]
            why.append("not from an app store (sideloaded, patched or cracked apps land here)")
        for label, pkgs in access.items():
            if pkg in pkgs and label in SCORES:
                weight = SCORES[label]
                score += weight
                why.append(label)
        if launcher_pkgs and pkg not in launcher_pkgs:
            score += SCORES["hidden"]
            why.append("no app icon (hidden from the app drawer)")
        last_update = (d.get("lastUpdateTime") or "")[:10]
        last_used, launches = used.get(pkg, ("", 0))
        try:
            age = (today - dt.date.fromisoformat(first)).days
        except ValueError:
            age = None
        if age is not None and age > 3 and not last_used and launches == 0:
            score += SCORES["unused"]
            why.append("never opened in the usage history")
        if age is not None and age <= 30:
            score += SCORES["recent"]
            why.append(f"installed {first}")
        try:
            if (today - dt.date.fromisoformat(last_update)).days > 730:
                score += SCORES["abandoned"]
                why.append(f"not updated since {last_update} (abandoned)")
        except ValueError:
            pass
        if JUNK_NAME.search(pkg):
            score += SCORES["utility"]
            why.append("cleaner/booster/VPN-type utility name (a common adware disguise)")
        if "android.permission.REQUEST_INSTALL_PACKAGES" in d["perms"] or pkg in access.get("_install", set()):
            score += SCORES["installer"]
            why.append("can install other apps")
        perms = d["perms"]
        full_screen = (pkg in access.get("_full_screen", set()) or
                       "android.permission.USE_FULL_SCREEN_INTENT" in perms) and (
                           pkg not in access.get("_full_screen_denied", set()))
        calling_alarm = bool(perms & {"android.permission.MANAGE_OWN_CALLS", "android.permission.CALL_PHONE",
                                      "android.permission.SET_ALARM", "android.permission.SCHEDULE_EXACT_ALARM",
                                      "android.permission.USE_EXACT_ALARM"})
        if full_screen and not calling_alarm:
            score += SCORES["full_screen"]
            why.append("full-screen intents allowed (verify this is a calling/alarm app)")
        if (launcher_pkgs and pkg not in launcher_pkgs and "android.permission.RECEIVE_BOOT_COMPLETED" in perms
                and any(p.startswith("android.permission.FOREGROUND_SERVICE") for p in perms)):
            score += SCORES["boot_service"]
            why.append("starts at boot with foreground service permission and no launcher icon")
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
        host = host_only("https://" + host)
        if host:
            rows.append((when.strftime("%Y-%m-%d"), host))
    return sorted(rows, reverse=True)


def host_only(url):
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def pinned_websites(text):
    """AOSP ShortcutInfo flags bit 1 is PINNED; never return labels, extras or URL paths."""
    hosts = set()
    for block in re.split(r"ShortcutInfo\s*\{", text)[1:]:
        flags = re.search(r"flags=0x([0-9a-fA-F]+)", block)
        if not flags or not int(flags.group(1), 16) & 2:
            continue
        # Match Intent data only, rather than URLs in titles/extras.
        intents = block.split("intents=", 1)[-1] if "intents=" in block else ""
        for url in re.findall(r"(?:dat=|data=)(https?://[^\s}\],]+)", intents):
            host = host_only(url)
            if host:
                hosts.add(host)
    return sorted(hosts)


def subscribed_calendars(text):
    """Only explicit subscription account types. Ordinary account/calendar names stay private."""
    rows = []
    for line in text.splitlines():
        fields = dict(re.findall(r"(account_type|calendar_displayName|account_name)=(.*?)(?=, (?:account_type|calendar_displayName|account_name)=|$)", line))
        kind = fields.get("account_type", "")
        if not SUBSCRIPTION_TYPE.search(kind):
            continue
        account = fields.get("account_name", "")
        domain = host_only("https://" + account.rsplit("@", 1)[1]) if "@" in account else host_only(account)
        rows.append({"account_type": kind, "display_name": fields.get("calendar_displayName", ""),
                     "account_domain": domain or "(masked)"})
    return rows


def notification_counts(text):
    """Bounded recent archive if present, otherwise current active NotificationRecords.

    Archive entries are lightweight StatusBarNotifications. Never count ranking/config rows,
    and never combine archive and active records (which can describe the same notification).
    """
    archive = re.search(r"(?ms)^ *Archive(?:\s*\(|:).*?(?=^  [A-Z][^\n]*:|\Z)", text)
    if archive:
        packages = re.findall(r"StatusBarNotification\(pkg=(" + PKG + r")\b", archive.group())
    else:
        packages = re.findall(r"NotificationRecord\([^\n]*?\bpkg=(" + PKG + r")\b", text)
    return Counter(packages)


def safe_notifications(text):
    """Persistence allowlist: no notification text, tags, extras or channel names."""
    lines = ["Notification service:"]
    for day, host in site_channels(text):
        # Retain the known Chromium channel format so the saved file is still parseable.
        stamp = int((dt.datetime.strptime(day, "%Y-%m-%d") - dt.datetime(1601, 1, 1)).total_seconds() * 1000000)
        lines.append("NotificationChannel{mId='web:https://%s;%s'}" % (host, stamp))
    for pkg, count in notification_counts(text).items():
        lines.extend(["NotificationRecord(pkg=" + pkg + ")"] * count)
    return "\n".join(lines) + "\n"


def device_findings(values, notif, rows, skipped):
    def unknown(name, reason="unrecognized or empty output"):
        if not any(x.startswith(CHECKS[name] + ":") for x in skipped):
            skipped.append(CHECKS[name] + ": " + reason)

    network = {}
    for name in ("proxy", "dns_mode", "dns_specifier", "always_on_vpn"):
        if values[name]:
            network[name] = values[name]
        else:
            unknown(name)
    vpn = values["vpn"]
    # AOSP VpnManagerService.dump / Vpn.dump. A selected package alone is not
    # evidence of an active tunnel; TYPE_VPN_NONE is -1.
    active = []
    for block in re.split(r"(?m)^\s*\d+: ", vpn)[1:]:
        package = re.search(r"(?m)^\s*Active package name: (" + PKG + r")\s*$", block)
        vpn_type = re.search(r"Active vpn type: (-?\d+)", block)
        if package and vpn_type and int(vpn_type.group(1)) > 0:
            active.append(package.group(1))
    if vpn.strip() == "VPNs:" or ("Active vpn type:" in vpn and "Active package name:" in vpn):
        network["active_vpn_apps"] = sorted(set(active))
    else:
        unknown("vpn", "active state unavailable; verify VPN in Settings")
    certs = values["certificates"]
    certificates = sorted(re.findall(r"(?m)^([0-9a-fA-F]+\.\d+)\s*$", certs))
    if certs and not certificates:
        unknown("certificates")
    shortcuts = values["shortcuts"]
    if not shortcuts or not re.search(r"Shortcut|User:", shortcuts):
        unknown("shortcuts")
    calendars = values["calendars"]
    if not calendars or not re.search(r"(?m)^(?:Row: \d+ |No result found)", calendars):
        unknown("calendars")
    elif any("account_type=" not in line for line in calendars.splitlines() if line.startswith("Row:")):
        unknown("calendars", "account types unavailable; check subscriptions in Calendar settings")
    if calendars.startswith("Row:") and any(
            not SUBSCRIPTION_TYPE.search(kind)
            for kind in re.findall(r"account_type=([^,\n]+)", calendars)):
        unknown("calendars", "provider does not identify every subscription; check Calendar settings manually")
    suspects = {r[1] for r in rows if r[0] >= 3}
    third = {r[1] for r in rows}
    sources = [{"package": p, "count": n, "suspect": p in third and p in suspects}
               for p, n in sorted(notification_counts(notif).items(), key=lambda item: (-item[1], item[0]))[:10]]
    # Only filtered metadata leaves memory; none of these raw dumps is written to disk.
    return {"network_settings": network, "user_certificates": certificates,
            "website_shortcuts": pinned_websites(shortcuts),
            "calendar_subscriptions": subscribed_calendars(calendars), "notification_sources": sources}


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
    "full_screen": "appops query-op USE_FULL_SCREEN_INTENT allow",
    "full_screen_denied": "appops query-op USE_FULL_SCREEN_INTENT ignore",
    "full_screen_blocked": "appops query-op USE_FULL_SCREEN_INTENT deny",
    "proxy": "settings get global http_proxy",
    "dns_mode": "settings get global private_dns_mode",
    "dns_specifier": "settings get global private_dns_specifier",
    "always_on_vpn": "settings get secure always_on_vpn_app",
    "vpn": "dumpsys vpn_management",
    "certificates": "ls /data/misc/user/0/cacerts-added",
    "shortcuts": "dumpsys shortcut",
    "calendars": "content query --uri content://com.android.calendar/calendars --projection account_type:calendar_displayName:account_name",

}
ERROR = re.compile(r"(?im)^\s*(?:error\b|usage:|unknown (?:command|operation|option)|"
                   r"(?:AppOps service|Role manager|Package manager).*commands:|Available commands:|"
                   r".*permission denied|.*no such file or directory|unsupported\b|not supported\b|(?:cmd: )?can't find service|cannot find service|"
                   r"exception\b|java\.[\w.]*exception|securityexception|permission denial|"
                   r"adb:|adb command failed|.*: (?:not found|inaccessible or not found))")
CHECKS = {"overlays": "draws over other apps", "admins": "device admin",
          "accessibility": "accessibility service", "listeners": "reads notifications",
          "home_role": "default home", "browser_role": "default browser",
          "installers": "install other apps", "launcher": "hidden app icons",
          "browsing": "browser activity discovery", "installed": "installed browsers",
          "full_screen": "full-screen intent appop", "full_screen_denied": "ignored full-screen intent appop",
          "full_screen_blocked": "denied full-screen intent appop",
          "proxy": "global HTTP proxy", "dns_mode": "private DNS mode", "dns_specifier": "private DNS specifier",
          "always_on_vpn": "always-on VPN", "vpn": "active VPN apps", "certificates": "user CA certificates (user 0)",
          "shortcuts": "pinned website shortcuts", "calendars": "subscribed calendars"}


def collect(phone):
    """Collect read-only outputs; no files or printing. Longer limits for large dumps."""
    raw = {}
    for name, command in COMMANDS.items():
        # Keep optional command failures in CHECKS SKIPPED, without echoing stderr payloads.
        with contextlib.redirect_stderr(io.StringIO()):
            raw[name] = phone.shell(command, timeout=180 if name in ("packages", "usage") else 60)
    return raw


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
              "_install": packages_in(values["installers"]),
              "default home": packages_in(values["home_role"]),
              "_full_screen": packages_in(values["full_screen"]),
              "_full_screen_denied": packages_in(values["full_screen_denied"]) | packages_in(values["full_screen_blocked"])}
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
    findings = device_findings(values, raw["notif"], rows, skipped)
    return {**findings, "device": {"model": parts[0] if parts else "?",
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
    for key, title in (("network_settings", "PROXY / PRIVATE DNS / VPN"),
                       ("user_certificates", "USER CA CERTIFICATES (USER 0)"),
                       ("website_shortcuts", "PINNED WEBSITE SHORTCUTS (HOST ONLY)"),
                       ("calendar_subscriptions", "SUBSCRIBED CALENDARS"),
                       ("notification_sources", "RECENT NOTIFICATION SOURCES (PACKAGE / COUNT)")):
        print("== " + title)
        findings = result[key]
        if isinstance(findings, dict):
            for name, value in findings.items():
                print(f"{name}: {value}")
        else:
            for finding in findings:
                if key == "calendar_subscriptions":
                    print(f"{finding['account_type']} | {finding['display_name']} | {finding['account_domain']}")
                elif key == "notification_sources":
                    print(f"{finding['package']} | {finding['count']}" + (" | SUSPECT" if finding['suspect'] else ""))
                else:
                    print(finding)
    print("   Notification counts cover the bounded recent archive, or active records when no archive is present; not a daily total.")
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
        (out / (name + ".txt")).write_text(safe_notifications(raw[name]) if name == "notif" else raw[name], encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print_summary(result, out, a.all)


if __name__ == "__main__":
    main()
