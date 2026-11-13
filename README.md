# Android Pop-up Cleanup for Claude Code and Codex

A plugin for repair shops that works in both Claude Code and OpenAI Codex. Plug in a customer's Android or Samsung Galaxy phone that's showing pop-ups, scam websites or fake virus and weather alerts. The agent finds where they're coming from, walks you through removing them, and prints a one-page report for the customer with **your shop's** name, logo and address.

This fork is maintained by Phone-Fix.com. The original was built at [Nerdy Neighbor](https://nerdyneighbor.net) in Prescott, AZ, from real customer phones.

![Sample report](docs/sample-report.png)

## Why the usual "remove the bad app" approach misses it

Pop-ups can come from more than an app. The skill checks these common sources:

1. **A hidden Samsung Routine.** A scam site adds a routine with an innocent name like "Playing games while charging" that opens a website whenever the phone charges. There's no app to uninstall, and antivirus apps don't see it.
2. **Browser site notifications.** Fake "weather alert", "package delivery" or "virus found" sites that the customer once tapped **Allow** on. The agent walks through clearing them in every browser triage lists: Chrome, Samsung Internet, Firefox, Edge, Brave and others.
3. **Apps.** Every third-party app gets a red-flag score. Sideloaded apps (patched or cracked "free premium" apps often carry adware) go to the top of the list. So do apps that draw over other apps, abuse device admin or accessibility, hide their icon, or were never opened, plus junk "cleaner", "booster" and "shield" apps. Store apps, carrier preloads and Smart Switch transfers are judged by their other red flags. Apps pushed by DT Ignite/Aura carrier installers get a separate flag.

Everything starts **read-only**. Nothing is uninstalled until you approve it, and the agent asks which apps the customer actually uses. Free games that show ads *inside* the game are left alone.

Routines checks are **Samsung Galaxy only**. On Motorola, Pixel and other Android phones, skip Routines and continue with apps, browser notifications and device settings. Samsung Internet steps apply only if installed. Android versions and manufacturers expose different checks; unsupported checks are listed as skipped. If pop-ups continue, inspect the manufacturer's own settings by hand and record what was not checked instead of calling the phone clean.

## What's different in this fork

- **Triage fails loudly.** Empty or malformed core app, usage or notification dumps stop `triage.py` with an error. Unsupported or unreadable optional checks appear under **CHECKS SKIPPED**. Never put those in the report's **Checked** table.
- **More app flags.** Triage flags sideloaded packages using Samsung/system-style names (`com.samsung.*` or `com.sec.*`), DT Ignite/Aura carrier-pushed apps, full-screen-intent access without calling/alarm permissions, hidden apps with boot/service permissions, notification listeners and third-party default home apps. These are leads to verify with the customer, not proof of adware; the calling/alarm exemption is a permission-based guess.
- **Device-level checks.** Global HTTP proxy, private DNS, always-on/active VPN settings, readable user CA certificate filenames (user 0 only), pinned website shortcut hosts, explicit calendar subscription account types and recent notification sources. Calendar checks query metadata, never events, and can miss subscriptions the provider doesn't identify. Unreadable certificate stores and incomplete checks need manual follow-up, including other user profiles.
- **One browser list.** `browsers.py` shares known browser packages between triage and `usage_events.py`, including beta variants. Browser discovery also checks installed apps and browser activities. Site-channel parsing covers Chrome-based channels; check Samsung Internet and other browser settings manually. Channels may remain after a site is blocked. Notification counts cover a bounded recent archive, or active records if there is no archive, not a daily total or proof of adware.
- **Guarded app removal.** `remove.py` requires `--serial` and `--job`, binds the job to the serial, model and Android ID, and refuses missing or system/preinstalled apps. It previews a plan without changing apps; the agent must show that exact plan and get the tech's yes before adding `--approved`. The flag records approval supplied by the caller; it does not collect consent itself.
- **Backups and a job trail.** Uninstall backs up every APK split to `backup/<package>/` first; a failed backup stops that package unless the tech explicitly approves `--no-backup`. `--restore` reinstalls the saved APKs, but cannot recover deleted app data, accounts or settings. `--disable` disables an app for user 0 instead; `--enable` undoes that. Restore, disable and enable use the same preview/approval flow. `device.json`, backups and `actions.log` stay with the job; review results and the final package list for failures.
- **Per-ticket comparisons and reports.** `job.py start` records a ticket and optional tech initials without overwriting an existing `job.json`. Before/after triage JSON feeds `job.py compare`, which writes `compare.json` with counts and removed/remaining/added items for comparable checks. Reports can use `--job` to prefill device, Android version, ticket, successful uninstall/disable actions and a **Before / after** table. Explicit report data wins, including empty lists. Review skipped checks before accepting comparisons. Triage no longer prints the serial and report prefill omits it; removal's local identity and action records still contain it.

## What you need

- **An AI coding agent:** either
  - **Claude Code** with a paid Claude plan (Pro or Max) or an API key: <https://claude.com/claude-code>, or
  - **OpenAI Codex CLI** with a ChatGPT plan (Plus, Pro, Business) or an API key: <https://github.com/openai/codex>
- **Python 3**
- **Android platform-tools (adb)**
- **Google Chrome, Microsoft Edge or Chromium**, used to print the PDF report
- A USB **data** cable. Many cheap cables are charge-only.

## Setup

### Windows
Open PowerShell and run:
```powershell
winget install Python.Python.3.12
winget install Google.PlatformTools
winget install Git.Git
```
Edge is already installed, so you don't need Chrome. Then install the agent you want:
```powershell
irm https://claude.ai/install.ps1 | iex                                                # Claude Code
powershell -ExecutionPolicy ByPass -c "irm https://chatgpt.com/codex/install.ps1 | iex"  # Codex
```

### macOS
```bash
brew install python android-platform-tools
```
No Homebrew? Get it at <https://brew.sh>. Then install the agent you want:
```bash
curl -fsSL https://claude.ai/install.sh | bash   # Claude Code
brew install --cask codex                        # Codex
```

### Linux
Install Python, adb (with its USB permission rules) and a browser for your distro:

| Distro | Command |
|---|---|
| Ubuntu, Debian, Mint, Pop!_OS | `sudo apt install python3 adb` and Google Chrome from <https://google.com/chrome> |
| Fedora | `sudo dnf install python3 android-tools chromium` |
| Arch, Manjaro, CachyOS, EndeavourOS | `sudo pacman -S python android-tools android-udev chromium`, then `sudo usermod -aG adbusers $USER` and log out and back in |
| openSUSE | `sudo zypper install python3 android-tools chromium` |

On Ubuntu, use the Chrome `.deb` rather than the Chromium snap. The snap's sandbox can get in the way of printing the report.

Then install the agent you want:
```bash
curl -fsSL https://claude.ai/install.sh | bash   # Claude Code
npm install -g @openai/codex                     # Codex (needs Node.js)
```

If `adb devices` shows `no permissions`, the USB rules aren't active yet. Unplug the phone, plug it back in, and try again. On Arch-based distros, also check that you logged out after joining `adbusers`.

## Install the plugin

### Claude Code
Start `claude` in a terminal, then type:
```
/plugin marketplace add phonefixdfw/android-cleanup
/plugin install android-cleanup@phonefixdfw-android-cleanup
```
Restart Claude Code.

### Codex
In a terminal:
```bash
codex plugin marketplace add phonefixdfw/android-cleanup
codex plugin add android-cleanup@phonefixdfw-android-cleanup
```

**Codex needs one setting.** Codex's sandbox blocks network connections by default, and adb talks to its own background service over a local connection. Without this setting, every adb command fails with `cannot connect to daemon`. Add these lines to `~/.codex/config.toml` (on Windows, `%USERPROFILE%\.codex\config.toml`):
```toml
[sandbox_workspace_write]
network_access = true
```
Before starting Codex, also run `adb start-server` once, so adb's background service runs outside the sandbox and can reach the USB port. The first time Codex saves your shop details, it asks permission to write outside the job folder. Approve it.

## Switching from the original plugin

On each shop PC with the original plugin installed, uninstall it and remove its marketplace, then install the fork. Run the commands for each agent you use on that PC.

### Claude Code

Start `claude`, then type:
```
/plugin uninstall android-cleanup@android-cleanup
/plugin marketplace remove android-cleanup
/plugin marketplace add phonefixdfw/android-cleanup
/plugin install android-cleanup@phonefixdfw-android-cleanup
```
Restart Claude Code.

### Codex

In a terminal:
```bash
codex plugin remove android-cleanup@android-cleanup
codex plugin marketplace remove android-cleanup
codex plugin marketplace add phonefixdfw/android-cleanup
codex plugin add android-cleanup@phonefixdfw-android-cleanup
```
Restart Codex.

## Updating

Update the fork on **each shop PC**, for each agent you use. Run these in a terminal:

```bash
claude plugin update android-cleanup@phonefixdfw-android-cleanup
codex plugin marketplace upgrade phonefixdfw-android-cleanup
```

Restart the agent afterward. PCs still using the original marketplace need the switching steps above first.

## Using it

1. **On the phone:** Settings → About phone (→ Software information on Samsung) → tap **Build number** 7 times. Then go to Settings → Developer options → turn on **USB debugging**.
2. Plug the phone in and tap **Allow** on the "Allow USB debugging?" prompt.
3. Make a separate folder for the ticket (for example `Documents/Cleanups/Ticket-123`), start `claude` or `codex` in it, and describe the problem:
   > Customer's Galaxy is plugged in. Pop-ups and a scam website keep opening by themselves, mostly when it's charging. Ticket 123, tech AB.
4. The agent runs `job.py start --ticket "123" --tech "AB"` from that folder if the ticket is known (`--tech` is optional). It runs read-only triage into `triage-before/` and saves `triage-before.json`. Review the findings and **CHECKS SKIPPED**. Keep the phone unlocked for screen checks; Routines inspection is manual and Samsung-only.
5. Before changing apps, the agent runs `remove.py --serial <serial> --job "<job-folder>" <package>` as a dry run (a valid preview exits nonzero pending approval; resolve any reported errors first). It shows you the exact plan and waits for your yes before rerunning with `--approved`. A changed package list or option needs a new preview and approval. If unsure, use `--disable`. The agent must use this helper rather than direct uninstall or app-data-clearing commands.
6. After cleanup, the agent saves `triage-after/` and `triage-after.json`, then runs `job.py compare triage-before.json triage-after.json` from the job folder. Check the comparison against browser settings and any skipped checks; counts alone cannot prove the phone is clean.
7. Ask for **the cleanup report**. The first time, the agent asks for your shop name, tagline, address, phone/website and logo, and saves `shop.json` and the logo in `~/.android-cleanup/`. Optional `shop.json` fields `warranty` and `reviewUrl` print a small warranty line and a review URL as text (no QR code); omit them to leave them out. See [shop-example.json](plugins/android-cleanup/skills/adware-cleanup/report/shop-example.json) for the format. `report/make_report.py data.json report.pdf --job "<job-folder>"` uses the job records to prefill the report; `--job` is optional. Only verified findings belong in `data.json`, and skipped checks must stay out of **Checked**. Review the report before printing.
8. Turn USB debugging back off before the customer leaves.

Script paths above are relative to the installed skill's folder, `plugins/android-cleanup/skills/adware-cleanup/` in this repo. The agent uses full script paths while keeping records in the job folder. On Windows use `py -3 -I`; on macOS/Linux use `python3 -I` before the script path. Device scripts use the phone's explicit serial, as described in the skill.

## Viewing a job in the browser

From the repository checkout, run:

```bash
python plugins/android-cleanup/skills/adware-cleanup/scripts/gui.py --job "/path/to/job"
```

Use `python3` on systems where Python 3 has that name. The viewer opens your browser
and prints a private `http://127.0.0.1:PORT/?token=...` URL. Keep that URL private;
use it again to open another tab. Add `--port 8765` for a fixed port, and press
Ctrl+C in the terminal to stop the viewer. It works offline without dependencies.

Job summaries refresh every two seconds as the agent writes them. The viewer shows
findings, skipped checks, before/after comparisons, removal history and PDF links;
missing records stay hidden. Serials require a reveal click; Android IDs are never
included. Raw diagnostic dumps and backups are never served. PDF reports and phone
screenshots can contain customer information, so use the viewer on a private shop screen.

The phone list is read-only. Explicitly select a phone before **Refresh screenshot**;
captures are saved locally under the job's `screens/` folder, at most once every ten
seconds. The viewer never taps, writes to the phone, removes apps, or controls the agent.

**Roadmap:** Step 1 is this read-mostly viewer. Future steps add (2) launching and
steering Claude Code or Codex with headless streaming, (3) an approval file bound to
the exact removal list and required by `remove.py`, plus a hook blocking raw
`adb uninstall`, `pm uninstall` and `pm clear`, and (4) Mac/Windows launchers.
Only Step 1 is implemented here.

## Privacy

The diagnostic scripts run on your computer and the phone; they do not upload the job themselves. **Your agent still sends what it reads to Anthropic (Claude Code) or OpenAI (Codex)**, just like any other session. That includes script summaries with app lists, device details, website hosts, calendar subscription metadata and app/activity information, plus any phone-settings screenshots it views and customer details you type in chat. Tell your customer, and use it only on phones you're authorized to service.

The workflow tells the agent to read only script summaries, never open raw dump files, and avoid notification-shade screenshots. Triage uses the default redacted notification dump and saves only allowlisted site-channel host/date and notification package records in `notif.txt`: no notification text, channel labels, tags or extras. Raw calendar, shortcut, VPN and certificate outputs stay in memory. Raw package and usage dumps still stay in the local job folder so helper scripts can parse them.

**JSON is not anonymous.** `triage-before.json` and `triage-after.json` can contain calendar `display_name` values, identifying domains/hosts (sites, shortcuts, calendars, proxy/DNS), device details and app/activity metadata. Job folders may also hold ticket/tech details, serial and Android ID in `device.json`, serials in `actions.log`, APK backups, screenshots and report data/HTML/PDF. Keep originals as shop records. Before sharing a summary copy, remove calendar display names and redact identifying hosts, device and app/activity metadata as needed; do not share raw dumps. Notification filtering reduces exposure but does not make the summaries or the agent session free of customer data.

## Tests

From the repo folder, run:

```bash
python -m unittest discover tests
```

Use `python3` if your system has no `python` command. Use `python3` if your system has no `python` command. The tests use synthetic fixtures and mocked device calls; they do not contact a phone. They cover triage failures and privacy filtering, detection, guarded removal/restore, job comparisons and report HTML/prefill. GitHub Actions runs the same suite on Linux, Windows and macOS with Python 3.8 and 3.12. These checks do not replace testing a repair's findings on the customer's phone.

## Changes

- **1.4.0:** Includes the merged triage failure/privacy hardening and device-free tests/CI (#2), guarded removal and APK restore (#3), expanded read-only detection and shared browser list (#4), per-ticket comparisons/report prefill and optional shop fields (#5), and Samsung-only Routines/non-Samsung guidance (#6). Sets plugin author/marketplace owner to Phone-Fix.com.
- **1.3.0:** Pointed marketplace installation, updates and plugin repository/homepage metadata at this fork (#1), retaining the upstream credit and MIT license.

## Credits

Maintained by Phone-Fix.com. Forked from [nerd-industries/android-cleanup](https://github.com/nerd-industries/android-cleanup) by Nerd Industries (Nerdy Neighbor, Prescott AZ), under the MIT license.

## License

MIT. Use it, change it, share it. No warranty: you're responsible for what's changed on a customer's phone.
