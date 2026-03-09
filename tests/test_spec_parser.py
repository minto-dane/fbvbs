from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from fbvbs_spec.generate import generate_outputs
from fbvbs_spec.parser import parse_spec_document
from fbvbs_spec.validate import EXPECTED_HYPERCALL_COUNT, EXPECTED_REQUIREMENT_COUNT, validate_spec


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = REPO_ROOT / "plan" / "fbvbs-design.md"


class SpecParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = parse_spec_document(SPEC_PATH)

    def test_requirement_count_matches_catalog(self) -> None:
        self.assertEqual(len(self.spec.requirements), EXPECTED_REQUIREMENT_COUNT)

    def test_hypercall_count_matches_catalog(self) -> None:
        self.assertEqual(len(self.spec.hypercalls), EXPECTED_HYPERCALL_COUNT)

    def test_no_validation_errors(self) -> None:
        self.assertEqual(validate_spec(self.spec), [])

    def test_command_page_layout_is_one_page(self) -> None:
        layouts = {layout.name: layout for layout in self.spec.layouts}
        self.assertEqual(layouts["fbvbs_command_page_v1"].size_bytes, 4096)

    def test_partition_state_machine_contains_destroy_transition(self) -> None:
        transitions = [transition for transition in self.spec.partition_transitions if transition.next_state == "Destroyed"]
        self.assertTrue(transitions)

    def test_requirement_verification_classes_are_normalized(self) -> None:
        requirement = next(item for item in self.spec.requirements if item.requirement_id == "FBVBS-REQ-0201")
        self.assertEqual(requirement.verification_classes, ("inspection", "proof"))


class GeneratorTests(unittest.TestCase):
    def test_generate_outputs_writes_expected_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            generate_outputs(SPEC_PATH, output)

            expected_files = [
                output / "spec.json",
                output / "requirements.json",
                output / "requirements.csv",
                output / "abi.json",
                output / "partition_state_machine.dot",
                output / "bindings" / "fbvbs_abi_v1.h",
                output / "bindings" / "fbvbs_abi_v1.rs",
            ]
            for path in expected_files:
                self.assertTrue(path.exists(), path)

            requirements = json.loads((output / "requirements.json").read_text(encoding="utf-8"))
            self.assertEqual(len(requirements), EXPECTED_REQUIREMENT_COUNT)

            with (output / "requirements.csv").open(encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertEqual(len(rows) - 1, EXPECTED_REQUIREMENT_COUNT)

            header_text = (output / "bindings" / "fbvbs_abi_v1.h").read_text(encoding="utf-8")
            self.assertIn("struct fbvbs_command_page_v1", header_text)
            self.assertIn("#define OK 0", header_text)
            self.assertIn("#define FBVBS_CMD_FLAG_SEPARATE_OUTPUT (1ULL << 0)", header_text)
            self.assertIn("#define FBVBS_CALL_PARTITION_CREATE 0x0001", header_text)


if __name__ == "__main__":
    unittest.main()
