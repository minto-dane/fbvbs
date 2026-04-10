#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


STORAGE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "check_storage_invariants.py"
LEAK = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "detect_page_leaks.py"


class StorageAndMemoryIntegrityToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_checks_storage_invariants(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-storage-invariant-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "storage.json"
            output = temp_dir / "report.json"
            self.write_json(
                input_path,
                {
                    "pools": [
                        {"pool_id": 1, "capacity_bytes": 4096, "allocated_bytes": 2048, "granularity_bytes": 1024, "vdisk_count": 1, "attached_vdisk_count": 1}
                    ],
                    "vdisks": [
                        {"vdisk_id": 9, "pool_id": 1, "size_bytes": 1024, "attached_vm_partition_id": 55}
                    ],
                },
            )
            result = subprocess.run(["python3", str(STORAGE), "--input", str(input_path), "--output", str(output)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["violation_count"], 1)

    def test_detects_page_leaks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-page-leak-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "memory.json"
            output = temp_dir / "report.json"
            self.write_json(
                input_path,
                {
                    "memory_objects": [
                        {"object_id": 1, "backing_page_count": 1, "backing_pages": [100]},
                    ],
                    "pages": [
                        {"page_id": 100, "allocated": True, "owner_object_id": 2},
                        {"page_id": 101, "allocated": True, "owner_object_id": 0},
                    ],
                },
            )
            result = subprocess.run(["python3", str(LEAK), "--input", str(input_path), "--output", str(output)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["leak_count"], 2)


if __name__ == "__main__":
    unittest.main()
