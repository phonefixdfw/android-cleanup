---
name: adware-cleanup
description: Use when a customer's Android or Samsung Galaxy phone connected over adb (USB debugging) shows pop-ups, adware, scam websites opening by themselves, fake virus or weather alerts, or unwanted ads outside apps, or when asked to check Samsung Modes and Routines for anything suspicious, or to write a printable phone cleanup report for the customer.
---

# Android Adware Cleanup (adb)

## Overview
**Samsung Modes and Routines exist only on Samsung Galaxy phones.** Use triage's model to identify the manufacturer; if unclear, have the tech confirm it in About phone. Workflow step 3 is Samsung-only. On Motorola, Pixel and other stock-like Android phones, skip it and go straight to site notifications, apps and the device-level checks below (proxy/DNS/VPN, shortcuts, calendar subscriptions and notification sources).

On modern Android the "adware" is usually **not an app**. Check these three sources, in order of how often they cause pop-ups:
1. **Malicious Samsung Routine.** A routine disguised as a preset (e.g. "Playing games while charging") whose action is **Go to website**, often hidden behind date conditions.
2. **Browser site notifications.** Spam sites (fake weather or package alerts, random subdomains) that were allowed to send notifications.
3. **Apps.** Sideloaded apps (patched or cracked versions of popular apps often bundle adware), draw-over-apps, device-admin or accessibility abuse, apps with no icon, or junk "cleaner", "booster" and "shield" utilities.

The phone is the customer's. Investigate read-only first. **Get the tech's OK before uninstalling apps.** Ask which apps the customer actually uses. Ads that stay inside a game they play are normal, so leave those apps installed.

## Setup (works on Windows, macOS and Linux)
- **Python:** on Windows run scripts with `py -3 -I` (or `python -I`); on macOS and Linux use `python3 -I`. Written as `PY` below. The scripts need only the standard library.
- **adb:** the scripts find it on PATH or in the usual platform-tools folders. `PY scripts/adbtools.py` prints the path they found. If `adb` isn't on PATH, use that full path for your own adb commands (in PowerShell: `& "C:\path\adb.exe" -s X ...`). If nothing is found, ask the tech where platform-tools is and set `ADB` to the full path.
- **Phone:** run `adb devices`. `unauthorized` means the tech must tap **Allow** on the phone's USB debugging prompt. Empty means USB debugging is off, or the cable is charge-only.
- Pass the serial to every command: `--serial <serial>` for scripts and `adb -s <serial>` for adb. Never use `ANDROID_SERIAL=X cmd`, because that fails in PowerShell.
- Scripts are in this skill's `scripts/` and `report/` folders. Use their full paths. The folder the session starts in is the per-ticket **job folder** (`<job>` below); keep all job records there. Run `PY scripts/job.py start --ticket "<id>" --tech "<initials>"` from that folder if the ticket is known (`--tech` is optional). Existing `job.json` is never overwritten. Reports also work without it. Put screenshots in this job folder, not in the skill folder.
- **Privacy:** read only script summaries; never cat/open raw dumps (`packages.txt`, `usage.txt`, `notif.txt`). Avoid screenshots of the notification shade. Do not change the customer’s lock-screen/status-bar notification-content settings.
- **Job viewer (optional):** when asked to open the job viewer, launch `PY "<full path to this skill>/scripts/gui.py" --job "<current job folder>"` in a separate terminal or background process, keep it running while the agent works, and show the tech the full command and private localhost URL it prints.
- **First run:** if `~/.android-cleanup/shop.json` doesn't exist, ask the tech for the shop details (see Report, step 1) at the start, while triage runs, so the job doesn't stall at the end.

## Workflow
1. **Triage (read-only):** `PY scripts/triage.py --serial X "<job>/triage-before" --json "<job>/triage-before.json"`. It reports device info, apps newest-first, overlay apps, device admins, accessibility services, notification listeners, proxy/private DNS/VPN settings, readable user CA certificates (user 0 only), pinned website shortcut hosts, explicit calendar subscription accounts (domain masked), recent notification package counts, a **suspect-app list** scoring every third-party app on red flags, the installed browsers, browser site-notification channels with the date each was granted, and recent ad and browser events. Add `--all` to see every app's score, or `--json <file>` to save the structured summary. Anything listed under **CHECKS SKIPPED** must not appear in the report’s **Checked** table.
2. **Find the pop-up's trigger:** `PY scripts/usage_events.py "<job>/triage-before/usage.txt" --date YYYY-MM-DD --around HH:MM`. On Samsung, a browser launching right after a `com.android.systemui` NOTIFICATION_INTERRUPTION, with no app in the foreground, is a reason to inspect **Routines**, not proof of one. On other phones, continue with notifications, apps and device-level checks. A browser launching right after an ad screen means someone clicked an in-game ad, which is benign.
3. **Routines (Samsung Galaxy only; skip on other phones):** the app has no launcher icon, so open it with `adb -s X shell am start -a com.samsung.android.app.routines.action.LAUNCH_ROUTINE_TAB -p com.samsung.android.app.routines`. Routine data can't be read over adb, so open each routine and screenshot it, scrolling to the end of the **Then** list. Delete any routine with **Go to website**, **Open app**, or date/"Get details from data" logic that the customer didn't create (Delete → confirm Delete). Check the **Modes** tab for custom modes too.
4. **Site notifications, in every browser triage lists:** by default remove **all** allowed sites, not just the spam ones. Keep a site only if the customer asks for it by name. Then turn off sites asking to send notifications at all.
   - **Chrome, Edge, Brave and other Chrome-based browsers:** ⋮ → Settings → Site settings → Notifications → expand **Allowed** and remove each site, then select **"Don't allow sites to send notifications"**. Site settings → **All sites** → trash icon → **Delete & reset** also clears the spam sites' stored data. Android keeps a site's channel after the browser blocks it, so the triage channel list overstates what's live.
   - **Samsung Internet:** ☰ → Settings → Sites and downloads → Notifications (older versions: Privacy → Site permissions → Notifications). Remove every site and turn off **Allow sites to ask**.
   - **Firefox:** ☰ → Settings → Site permissions → Notifications, set to **Blocked**. Then go to Settings → Delete browsing data, tick **Site settings** and delete.
   - Menus move between versions. Use `ui.py find` to locate the right item.
5. **Apps:** start with the suspect list, including the new spoofed-system-name, carrier-push, full-screen-intent, boot/service, notification-listener and default-HOME flags. **Recommend removing every sideloaded app** unless the customer knows what it is and needs it. Patched and cracked apps ("free" premium YouTube, Spotify or games) are common adware carriers, even when the app itself works. Play Store, Galaxy Store, carrier and Smart Switch apps are trusted sources. Judge those by their red flags and by whether the customer uses them. Never remove an app the customer uses without asking.
   - Run a dry run: `PY scripts/remove.py --serial X --job "<job-folder>" com.example.app com.example.other`. Use the same job folder throughout the repair. The script binds it to the phone's serial, model and Android ID, refuses system/preinstalled or missing apps, and prints each package's label (if available), install source and version. A dry run exits non-zero because approval is required.
   - **Show that exact plan to the tech in chat and wait for a yes.** Only then rerun the same package list and options with `--approved`: `PY scripts/remove.py --serial X --job "<job-folder>" --approved com.example.app com.example.other`. A changed list or action needs a new dry run and approval. **The agent must never call `adb uninstall`, `pm uninstall` or `pm clear` directly.**
   - When the tech is unsure, offer `--disable` instead of uninstalling; follow the same dry run → show plan → approval flow. This disables the app for user 0. Undo with `--enable`, again previewing and approving the exact plan.
   - Uninstall first backs up every APK split under `<job-folder>/backup/<pkg>/`. A failed backup stops removal of that package. Use `--no-backup` only after showing the tech that removal may have no APK restore and getting approval for that option. APK backups do **not** preserve app data, accounts or settings; uninstall can delete them.
   - Restore APKs with `PY scripts/remove.py --serial X --job "<job-folder>" --restore com.example.app`, show the plan, then rerun with `--approved` after a yes. Restore uses `adb install-multiple` from the complete backup; it does not recover deleted app data. Keep `device.json`, backups and `actions.log` with the job for the report and shop records. The script reports per-package results and re-lists third-party packages at the end; check failures before claiming success. For `DELETE_FAILED_DEVICE_POLICY_MANAGER`, have the tech turn off the app's device-admin permission using the advice below, then rerun the approved removal.


### Follow up on new triage findings
- **Proxy, private DNS and VPN:** ask whether the customer recognizes the provider or work/school configuration. Verify in Settings → Network/Connections → Proxy, Private DNS and VPN (including always-on). Have the tech remove or correct unwanted configurations with the customer's approval; the triage commands only read settings. User CA results cover user 0 only: verify other profiles and Settings → Security → Encryption & credentials → User credentials manually. An unreadable certificate directory is skipped, never a clean bill of health.
- **Website shortcuts:** long-press unwanted website icons on the home screen and remove the shortcut after confirming with the customer. Triage prints only the host; it does not inspect pages or print URL paths.
- **Calendar subscriptions:** Calendar app → Settings → subscribed calendars. Unsubscribe from unwanted calendars after confirming with the customer. ADB only queries calendar metadata, never events; it reports explicit subscription account types and masks account names to domains. Many providers (including Google) do not identify subscriptions in these columns, so check manually when skipped or incomplete.
- **Full-screen-intent apps:** Settings → Apps → Special app access → Full-screen notifications/intents. Confirm that flagged apps really need calling/alarm behavior and have the tech revoke unwanted access. The calling/alarm exemption uses granted calling/exact-alarm permissions as a heuristic; verify manually. A boot/service flag or third-party HOME role also warrants checking the app with the customer. Notification counts cover only the bounded recent archive (or active records if absent), not a fixed time window or proof of adware.
- Samsung Internet's site channel IDs are not confidently identified; retain the manual browser steps above. **Skipped checks never go in the report's Checked table.** New calendar, shortcut, VPN and certificate dumps stay in memory; saved `notif.txt` contains only allowlisted channel host/date and package records, without notification text, labels, tags or extras.

## Non-Samsung phones
- Motorola and Pixel run near-stock Android: the app, browser-notification, usage-timeline and removal workflow applies unchanged. Follow Samsung Internet steps only if it is installed.
- If pop-ups continue and nothing is found, **do not claim the phone is clean**. Tell the tech which sources could not be checked, including uninspected OEM-specific features, and list them under **What was NOT checked**. Ask the tech to inspect manufacturer-specific settings by hand: the brand's own assistant/utility app, lock-screen or ad features, and Digital Wellbeing or focus-mode style automations, where present. These are places to look, not known causes.
- Ask the tech to keep the job's `triage-before.json` from every Motorola/Pixel pop-up case so detection can be tuned later. It excludes notification text, but is **not free of customer data**: before sharing a copy, remove calendar `display_name` values and redact identifying domains/hosts (including sites, shortcuts, calendars, proxy/DNS), device details and app/activity metadata as needed. Keep the original in the job folder; do not share raw dumps.


## Driving the screen
- Wake the screen first with `adb -s X shell input keyevent KEYCODE_WAKEUP`. If the screenshot shows the lock screen, ask the tech to unlock the phone.
- Screenshot: `PY scripts/ui.py --serial X shot <scratch>/s.png`, then view the image. Don't redirect `adb exec-out screencap` with `>`, because PowerShell corrupts the PNG. The image is shown scaled, so multiply coordinates by the factor noted with the image.
- Tap targets: `PY scripts/ui.py --serial X find "pattern"` prints `(x,y)` in real pixels. Tap with `adb -s X shell input tap x y`. Type with `adb -s X shell input text word`, sending spaces as `%s`.
- Finish on the home screen: `adb -s X shell input keyevent HOME`.

## Report (printable, black and white)
1. **Shop details:** the first time, ask the tech for the shop name, a short tagline, address, phone/website and logo file. Save to `~/.android-cleanup/shop.json` using `report/shop-example.json`; copy the logo next to it. Optional `warranty` prints a small line above the footer; optional `reviewUrl` prints as text (no QR). Omit either to leave it out.
2. After cleanup, run `PY scripts/triage.py --serial X "<job>/triage-after" --json "<job>/triage-after.json"`. From the job folder run `PY scripts/job.py compare "<job>/triage-before.json" "<job>/triage-after.json"`. This prints counts and removed/remaining/added items and writes `<job>/compare.json`. Missing or skipped checks are omitted. Channels can persist after blocking: confirm browser settings before claiming sites are allowed. Network changes and recent notification counts are observations, not proof of adware or a clean phone.
3. Write `<job>/data.json` with **only what you verified**; use `report/example-data.json` as a format reference, never as verified customer findings. `--job` prefills Device/Android from `triage-before.json`, Ticket from optional `job.json`, successful uninstall/disable rows from `actions.log`, and Before / after from `compare.json`. Explicit data fields win, including empty lists; individual `info` cells override by label. Omit fields to accept prefill. Missing job files are fine. Serial is not prefilled. Labels from logs require `label_verified: true`; otherwise packages print in backticks. Disabled apps are explicitly marked. Never invent app names or put skipped checks in Checked. Leave Customer as `""` for a write-in line. Cell text supports `**bold**` and `` `mono` ``.
4. `PY report/make_report.py "<job>/data.json" "<job>/Phone-Cleanup-Report-YYYY-MM-DD.pdf" --job "<job>"`. `--job` is optional. It prints with Chrome or Edge and fails unless the PDF is exactly one page. Keep it pure black on white: no colors or gray fills. Shorten text if necessary.
5. Check the PDF and open it for the tech: `Start-Process "<pdf>"` in PowerShell, `open "<pdf>"` on macOS, or `xdg-open "<pdf>"` on Linux. The agent reads structured summaries only, never opens raw dump files; helper scripts may parse them.

## End-of-job checklist
- After-triage and `job.py compare` completed; failures or skipped checks reviewed.
- Any `--disable`d apps listed for the tech, including how to re-enable with the approved removal workflow.
- Phone returned to the home screen.
- Tell the tech to turn **USB debugging off**.
- Report PDF opened for the tech to review and print.

## Common mistakes
| Mistake | Fix |
|---|---|
| Blaming the free games with heavy in-app ads | Inside-app ads are normal. Look for pop-ups *outside* apps. |
| Stopping at the app list | Check site notifications and device-level findings too; check Routines on Samsung Galaxy only. |
| Deleting every app that isn't from the Play Store | Smart Switch transfers, carrier preloads and Galaxy Store apps also have no Play installer, and they're fine. Remove *sideloaded* ones. |
| Cleaning only Chrome | Clear site notifications in every browser triage lists, including Firefox, Edge and Brave. |
| Treating every `web:` channel as active | Confirm in Chrome's Allowed list. Most may already be blocked. |
| Uninstalling without asking | Use `remove.py --serial X --job "<job-folder>"` for a dry run, show the exact plan to the tech, then rerun with `--approved` only after a yes. Never call `adb uninstall`, `pm uninstall` or `pm clear` directly. |
| Uninstall fails with `DELETE_FAILED_DEVICE_POLICY_MANAGER` | The app is a device admin. Turn it off in Settings → Security and privacy → Other security settings → Device admin apps, then uninstall again. |
| `adb devices` shows `no permissions` (Linux) | Install the distro's adb udev rules (Debian/Ubuntu: `adb`; Arch: `android-udev`; Fedora: `android-tools`), then unplug and replug the phone. |
| adb fails with `cannot connect to daemon` inside a sandbox (Codex) | The sandbox blocks adb's local connection. Ask the tech to set `[sandbox_workspace_write] network_access = true` in `~/.codex/config.toml`, run `adb start-server` outside the agent, and restart it. |
| adb keeps dropping, or the device shows `offline` | Bad cable or port. Ask for a different data cable, plugged straight into the computer instead of a hub. |
