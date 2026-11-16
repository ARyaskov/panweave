"""The footprint oracle must reject unsuccessful or incomplete QEMU runs."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lite_footprint import qemu


VALID_LOG = """PANWEAVE-LITE-QEMU
result formed=true joined=true reported=true rejoined=true restarted=true
dlk true
phase 100 construction
phase 200 initialization
phase 300 commissioning
phase 400 report
phase 500 parent loss and rejoin
phase 600 restart from flash
entry 100 new
entry 200 initialize
entry 300 commission
entry 400 on_radio_frame
entry 500 on_tx_complete
entry 600 next_radio_action
entry 700 poll
entry 800 set_inputs
entry 900 next_event
dropped device=0 stack=0 zcl=0 zdo=0 aps_actions=0 aps_events=0
virtual_ms 10000
"""


class QemuOracleTests(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qemu.log"
            path.write_bytes(text.encode("utf-8"))
            return qemu(path)

    def assert_invalid(self, text, reason):
        with self.assertRaisesRegex(SystemExit, reason):
            self.parse(text)

    def test_complete_successful_runs_accept_both_dlk_settings_and_crlf(self):
        for dlk in ("true", "false"):
            with self.subTest(dlk=dlk):
                result = self.parse(VALID_LOG.replace("dlk true", f"dlk {dlk}").replace("\n", "\r\n"))
                self.assertEqual(result["dlk"], dlk)
                self.assertEqual(result["phases"]["parent loss and rejoin"], 500)
                self.assertEqual(result["entries"]["on_radio_frame"], 400)

    def test_each_failed_scenario_outcome_is_rejected(self):
        for outcome in ("formed", "joined", "reported", "rejoined", "restarted"):
            with self.subTest(outcome=outcome):
                self.assert_invalid(VALID_LOG.replace(f" {outcome}=true", f" {outcome}=false"), f"scenario failed: {outcome}")

    def test_each_queue_loss_is_rejected(self):
        for counter in ("device", "stack", "zcl", "zdo", "aps_actions", "aps_events"):
            with self.subTest(counter=counter):
                self.assert_invalid(VALID_LOG.replace(f"{counter}=0", f"{counter}=1"), f"dropped queue entries: {counter}")

    def test_truncated_and_duplicate_summary_lines_are_rejected(self):
        for prefix in ("result ", "dlk ", "dropped "):
            original = next(line for line in VALID_LOG.splitlines() if line.startswith(prefix))
            with self.subTest(prefix=prefix, defect="missing"):
                self.assert_invalid(VALID_LOG.replace(original + "\n", ""), f"exactly one {prefix.strip()} line")
            with self.subTest(prefix=prefix, defect="duplicate"):
                self.assert_invalid(VALID_LOG + original + "\n", f"exactly one {prefix.strip()} line")

    def test_omitted_or_duplicate_measurements_are_rejected(self):
        for original in VALID_LOG.splitlines():
            if original.startswith(("phase ", "entry ")):
                kind = original.split()[0]
                with self.subTest(measurement=original, defect="missing"):
                    self.assert_invalid(VALID_LOG.replace(original + "\n", ""), f"{kind} measurements differ: missing")
                with self.subTest(measurement=original, defect="duplicate"):
                    self.assert_invalid(VALID_LOG + original + "\n", f"duplicate {kind} measurement")

    def test_malformed_and_zero_measurements_are_rejected(self):
        for replacement, reason in (
            ("phase -1 construction", "malformed phase measurement"),
            ("phase unknown construction", "malformed phase measurement"),
            ("phase 0 construction", "unmeasured phase: construction"),
            ("phase 100 nonexistent", "phase measurements differ"),
        ):
            with self.subTest(replacement=replacement):
                self.assert_invalid(VALID_LOG.replace("phase 100 construction", replacement), reason)

    def test_missing_unknown_duplicate_and_malformed_fields_are_rejected(self):
        for before, after, reason in (
            (" restarted=true", "", "result fields differ"),
            ("restarted=true", "unknown=true", "result fields differ"),
            ("restarted=true", "formed=true", "duplicate result field: formed"),
            ("restarted=true", "restarted=yes", "malformed result field"),
            ("aps_events=0", "aps_events=-1", "malformed dropped field"),
            ("dlk true", "dlk enabled", "dlk must be true or false"),
        ):
            with self.subTest(after=after):
                self.assert_invalid(VALID_LOG.replace(before, after), reason)

    def test_absent_or_repeated_probe_markers_are_rejected(self):
        self.assert_invalid("", "exactly one PANWEAVE-LITE-QEMU marker")
        self.assert_invalid(VALID_LOG + VALID_LOG, "exactly one PANWEAVE-LITE-QEMU marker")


if __name__ == "__main__":
    unittest.main()
