"""Device-free per-ticket records. Run from the folder the session started in.

python job.py start --ticket ID [--tech INITIALS]
python job.py compare triage-before.json triage-after.json
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


ACCESS = {"draws over other apps": "Overlay holders", "device admin": "Device admin holders",
          "accessibility service": "Accessibility holders", "reads notifications": "Notification listener holders"}
OPTIONAL = {"user_certificates": "User CA certificates", "website_shortcuts": "Pinned website shortcuts",
            "calendar_subscriptions": "Calendar subscriptions", "notification_sources": "Recent notification sources"}
CHECKS = {"user_certificates": "user CA certificates (user 0)", "website_shortcuts": "pinned website shortcuts",
          "calendar_subscriptions": "subscribed calendars", "proxy": "global HTTP proxy",
          "dns_mode": "private DNS mode", "dns_specifier": "private DNS specifier",
          "always_on_vpn": "always-on VPN", "active_vpn_apps": "active VPN apps"}


def mapping(value):
    return value if isinstance(value, dict) else {}


def mapping(value):
    return value if isinstance(value, dict) else {}


def available(data, key):
    label = CHECKS.get(key, key)
    return not any(str(s).startswith(label + ":") for s in (data.get("skipped_checks") or []))


def items_diff(before, after):
    # Counter preserves multiple channels for the same host; ordering does not affect comparison.
    def counter(items):
        return Counter(json.dumps(x, sort_keys=True, ensure_ascii=True) for x in items)
    old, new = counter(before), counter(after)
    def unpack(items):
        return [json.loads(x) for x in sorted(items) for _ in range(items[x])]
    return dict(before=len(before), after=len(after), removed=unpack(old - new),
                remaining=unpack(old & new), added=unpack(new - old))


def compare(before, after):
    """Compare only shared, available summary fields. Never read dumps or contact adb."""
    metrics = {}
    def add(key, label, old, new):
        metrics[key] = dict(label=label, **items_diff(old, new))
    if isinstance(before.get("site_channels"), list) and isinstance(after.get("site_channels"), list):
        add("site_channels", "Site-notification channels", before["site_channels"], after["site_channels"])
    if all(isinstance(d.get("suspects"), list) for d in (before, after)):
        for key, label, predicate in (
                ("sideloaded", "Sideloaded apps", lambda r: str(r.get("source", "")).startswith("SIDELOADED")),
                ("suspects", "Suspect apps (score >= 3)", lambda r: isinstance(r.get("score"), (int, float)) and r["score"] >= 3)):
            rows = [[r["package"] for r in d["suspects"] if isinstance(r, dict) and r.get("package") and predicate(r)]
                    for d in (before, after)]
            add(key, label, *rows)
    for key, label in ACCESS.items():
        values = [mapping(d.get("access")).get(key) for d in (before, after)]
        if all(isinstance(v, list) for v in values) and all(available(d, key) for d in (before, after)):
            add(key, label, *values)
    for key, label in OPTIONAL.items():
        values = [d.get(key) for d in (before, after)]
        if all(isinstance(v, list) for v in values) and all(available(d, key) for d in (before, after)):
            add(key, label, *values)
    network = {}
    old, new = mapping(before.get("network_settings")), mapping(after.get("network_settings"))
    for key in sorted(old.keys() & new.keys()):
        if old[key] is not None and new[key] is not None and all(available(d, key) for d in (before, after)):
            network[key] = dict(before=old[key], after=new[key])
            if isinstance(old[key], list) and isinstance(new[key], list):
                network[key].update(items_diff(old[key], new[key]))
    return dict(metrics=metrics, network_settings=network)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start")
    start.add_argument("--ticket", required=True)
    start.add_argument("--tech")
    diff = commands.add_parser("compare")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "start":
            record = dict(ticket=args.ticket, started=datetime.now(timezone.utc).isoformat())
            if args.tech:
                record["tech"] = args.tech
            # Do not silently reassign an existing ticket folder.
            with Path("job.json").open("x", encoding="utf-8") as stream:
                json.dump(record, stream, indent=2)
                stream.write("\n")
            print("wrote job.json")
        else:
            result = compare(json.loads(args.before.read_text(encoding="utf-8")),
                             json.loads(args.after.read_text(encoding="utf-8")))
            Path("compare.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            for row in result["metrics"].values():
                print("{}: {} -> {}".format(row["label"], row["before"], row["after"]))
                for key in ("removed", "remaining", "added"):
                    print("  {}: {}".format(key, json.dumps(row[key], ensure_ascii=True)))
            for key, row in result["network_settings"].items():
                print("{}: {} -> {}".format(key, json.dumps(row["before"]), json.dumps(row["after"])))
            print("Channel counts can include blocked sites; verify browser settings. Notification counts are a bounded recent snapshot.")
            print("wrote compare.json")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print("Job record failed: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
