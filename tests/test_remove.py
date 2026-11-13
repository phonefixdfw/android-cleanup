"""Guarded removal tests. All adb calls are fake; never discover or contact a device."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = (Path(__file__).resolve().parents[1] / "plugins/android-cleanup/skills/"
          "adware-cleanup/scripts/remove.py")
SPEC = importlib.util.spec_from_file_location("cleanup_remove", SCRIPT)
remove = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remove)
APP = "com.example.adware"
SYSTEM = "com.android.settings"


class RemoveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.job = Path(self.temp.name)
        self.calls = []
        self.installed = {APP, SYSTEM}
        self.third = {APP}
        self.android_id = "1234abcd"
        self.pull_fails = False
        self.split_fails = False
        self.policy = False
        self.swap_after_pull = False
        self.output = io.StringIO()
        def initialize(phone, serial):
            phone.serial = serial
            phone.adb = "fake-adb-never-executed"
        patches = [mock.patch.object(remove.Phone, "__init__", initialize),
                   mock.patch.object(remove.Phone, "raw", side_effect=self.raw),
                   mock.patch.object(remove.Phone, "shell", side_effect=AssertionError("shell string used")),
                   contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output)]
        for patch in patches:
            patch.__enter__()
            self.addCleanup(patch.__exit__, None, None, None)

    def raw(self, *args):
        self.calls.append(args)
        if args == ("get-state",):
            return b"device\n"
        if args == ("get-serialno",):
            return b"TEST-SERIAL\n"
        if args == ("shell", "getprop", "ro.product.model"):
            return b"Fake phone\n"
        if args == ("shell", "settings", "get", "secure", "android_id"):
            return self.android_id.encode()
        if args[:4] == ("shell", "pm", "list", "packages"):
            source = self.third if "-3" in args else self.installed
            return "\n".join("package:" + name for name in sorted(source)).encode()
        if args[:3] == ("shell", "dumpsys", "package"):
            return b"  label=Fake App\n versionName=1.2\n versionCode=12\n installerPackageName=com.android.vending\n"
        if args[:3] == ("shell", "pm", "path"):
            return b"package:/data/app/example/base.apk\npackage:/data/app/example/split_config.apk\n"
        if args[0] == "pull":
            if self.pull_fails or (self.split_fails and "split_config" in args[1]):
                raise remove.SafetyError("fake pull failed")
            Path(args[2]).write_bytes(b"fake APK " + args[1].encode())
            if self.swap_after_pull:
                self.android_id = "5678abcd"
            return b"1 file pulled"
        if args[0] == "uninstall":
            if self.policy:
                return b"Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]"
            self.installed.discard(args[1])
            self.third.discard(args[1])
            return b"Success\n"
        if args[0] == "install-multiple":
            self.installed.add(APP)
            self.third.add(APP)
            return b"Success\n"
        if args[:3] == ("shell", "pm", "disable-user"):
            return ("Package " + args[-1] + " new state: disabled-user").encode()
        if args[:3] == ("shell", "pm", "enable"):
            return ("Package " + args[-1] + " new state: enabled").encode()
        raise AssertionError("Unexpected fake adb call: " + repr(args))

    def run_cli(self, *args):
        return remove.main(["--serial", "TEST-SERIAL", "--job", str(self.job)] + list(args))

    def mutations(self):
        return [call for call in self.calls if call[0] in ("uninstall", "install-multiple")
                or call[:3] in (("shell", "pm", "disable-user"), ("shell", "pm", "enable"))]

    def logs(self):
        return [json.loads(line) for line in (self.job / "actions.log").read_text().splitlines()]

    def test_refuses_system_package_before_any_removal(self):
        self.assertEqual(1, self.run_cli("--approved", APP, SYSTEM))
        self.assertEqual([], self.mutations())
        self.assertIn("not a third-party", self.output.getvalue())

    def test_refuses_missing_package(self):
        self.assertEqual(1, self.run_cli("--approved", "com.example.missing"))
        self.assertEqual([], self.mutations())

    def test_dry_run_requires_approval_and_prints_metadata(self):
        self.assertEqual(1, self.run_cli(APP))
        self.assertEqual([], self.mutations())
        self.assertFalse(any(call[0] == "pull" for call in self.calls))
        for value in (APP, "Fake App", "1.2", "com.android.vending", "--approved"):
            self.assertIn(value, self.output.getvalue())

    def test_device_binding_and_mismatch_refusal(self):
        self.run_cli(APP)
        identity = json.loads((self.job / "device.json").read_text())
        self.assertEqual(dict(serial="TEST-SERIAL", model="Fake phone", android_id="1234abcd"), identity)
        self.android_id = "5678abcd"
        self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertEqual([], self.mutations())
        self.assertIn("Device mismatch", self.output.getvalue())

    def test_unknown_identity_refuses(self):
        self.android_id = "null"
        self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertEqual([], self.mutations())

    def test_backup_failure_stops_removal(self):
        self.pull_fails = True
        self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertEqual([], self.mutations())
        self.assertFalse((self.job / "backup" / APP / "manifest.json").exists())

    def test_no_backup_explicit_override(self):
        self.pull_fails = True
        self.assertEqual(0, self.run_cli("--approved", "--no-backup", APP))
        self.assertIn(("uninstall", APP), self.mutations())
        self.assertTrue(any(item["action"] == "backup" and "failed" in item["result"] for item in self.logs()))

    def test_partial_split_backup_stops_removal(self):
        self.split_fails = True
        self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertEqual([], self.mutations())
        self.assertEqual(2, len([call for call in self.calls if call[0] == "pull"]))
        self.assertFalse((self.job / "backup" / APP / "manifest.json").exists())

    def test_failure_is_reported_and_next_package_continues(self):
        other = "com.example.other"
        self.installed.add(other)
        self.third.add(other)
        original = self.raw
        def fail_first(*args):
            if args == ("uninstall", APP):
                self.calls.append(args)
                raise remove.SafetyError("DELETE_FAILED_INTERNAL_ERROR")
            return original(*args)
        with mock.patch.object(remove.Phone, "raw", side_effect=fail_first):
            self.assertEqual(1, self.run_cli("--approved", APP, other))
        self.assertIn(("uninstall", other), self.mutations())
        self.assertIn("DELETE_FAILED_INTERNAL_ERROR", self.output.getvalue())
        self.assertTrue(any(item["package"] == other and item["result"].startswith("success")
                            for item in self.logs()))

    def test_unwritable_audit_log_prevents_mutation(self):
        with mock.patch.object(remove, "log", side_effect=OSError("audit disk full")):
            self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertEqual([], self.mutations())
        self.assertFalse(any(call[0] == "pull" for call in self.calls))

    def test_success_logs_and_backs_up_every_split(self):
        self.assertEqual(0, self.run_cli("--approved", APP))
        manifest = json.loads((self.job / "backup" / APP / "manifest.json").read_text())
        self.assertEqual(2, len(manifest["files"]))
        for item in manifest["files"]:
            self.assertTrue((self.job / "backup" / APP / item["file"]).is_file())
        entries = self.logs()
        for item in entries:
            self.assertTrue({"timestamp", "serial", "package", "action", "result"} <= item.keys())
            self.assertEqual("TEST-SERIAL", item["serial"])
        self.assertTrue(any(item["action"] == "uninstall" and item["result"].startswith("success") for item in entries))
        self.assertEqual("verify", entries[-1]["action"])

    def test_swap_after_backup_stops_uninstall(self):
        self.swap_after_pull = True
        self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertEqual([], self.mutations())

    def test_disable_and_enable_skip_backup(self):
        self.assertEqual(0, self.run_cli("--disable", "--approved", APP))
        self.assertEqual(0, self.run_cli("--enable", "--approved", APP))
        self.assertFalse(any(call[0] == "pull" for call in self.calls))
        self.assertEqual(2, len(self.mutations()))

    def test_policy_failure_gives_settings_advice(self):
        self.policy = True
        self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertIn("Device admin apps", self.output.getvalue())
        self.assertTrue(any("DELETE_FAILED_DEVICE_POLICY_MANAGER" in item["result"] for item in self.logs()))

    def test_restore_requires_approval_and_uses_all_splits(self):
        self.assertEqual(0, self.run_cli("--approved", APP))
        self.calls.clear()
        self.assertEqual(1, self.run_cli("--restore", APP))
        self.assertEqual([], self.mutations())
        self.assertEqual(0, self.run_cli("--restore", "--approved", APP))
        install = [call for call in self.calls if call[0] == "install-multiple"][0]
        self.assertEqual("-r", install[1])
        self.assertEqual(2, len(install[2:]))

    def test_tampered_backup_refuses_restore(self):
        self.run_cli("--approved", APP)
        Path(remove.restore_files(self.job, APP)[0]).write_bytes(b"corrupt")
        self.calls.clear()
        self.assertEqual(1, self.run_cli("--restore", "--approved", APP))
        self.assertEqual([], self.mutations())

    def test_missing_backup_refuses_restore(self):
        self.assertEqual(1, self.run_cli("--restore", "--approved", APP))
        self.assertEqual([], self.mutations())

    def test_false_success_detected_by_final_package_list(self):
        original = self.raw
        def false_success(*args):
            if args == ("uninstall", APP):
                return b"Success\n"
            return original(*args)
        with mock.patch.object(remove.Phone, "raw", side_effect=false_success):
            self.assertEqual(1, self.run_cli("--approved", APP))
        self.assertIn("FAILED final verification", self.output.getvalue())

    def test_empty_invalid_and_duplicate_lists_refused(self):
        for args in ((), ("com.example.app;reboot",), ("../bad",), (APP, APP)):
            with self.subTest(args=args), self.assertRaises(SystemExit) as exc:
                self.run_cli(*args)
            self.assertEqual(2, exc.exception.code)
        self.assertEqual([], self.calls)

    def test_serial_is_required(self):
        with self.assertRaises(SystemExit) as exc:
            remove.main(["--job", str(self.job), APP])
        self.assertEqual(2, exc.exception.code)
        self.assertEqual([], self.calls)


class AdbTransportTests(unittest.TestCase):
    def test_argument_lists_status_and_timeout_without_device(self):
        with mock.patch.object(remove, "BasePhone"):
            phone = object.__new__(remove.Phone)
            phone.adb, phone.serial = "fake adb", "TEST-SERIAL"
        with mock.patch.object(remove.subprocess, "run") as process:
            process.return_value = subprocess.CompletedProcess([], 1, b"", b"fake failure")
            with self.assertRaisesRegex(remove.SafetyError, "fake failure"):
                phone.raw("shell", "pm", "list", "packages", "-3")
            process.assert_called_once_with(
                ["fake adb", "-s", "TEST-SERIAL", "shell", "pm", "list", "packages", "-3"],
                capture_output=True, timeout=120)


if __name__ == "__main__":
    unittest.main()
