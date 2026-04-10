#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


GENERATE_AUTH = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "generate_storage_authorization_model.py"
GENERATE_LIFECYCLE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "generate_vdisk_lifecycle_model.py"
VERIFY_AUDIT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "verify_storage_attach_detach_audit.py"
ISSUE_CONFIRM = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "issue_destructive_storage_confirmation.py"
VERIFY_CONFIRM = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "verify_destructive_storage_confirmation.py"
GENERATE_TRAIL = pathlib.Path(__file__).resolve().parents[3] / "tools" / "storage" / "generate_storage_evidence_trail.py"
ISSUE_ORIGIN = pathlib.Path(__file__).resolve().parents[3] / "tools" / "security" / "issue_command_origin_attestation.py"


class StorageGovernanceToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_generates_storage_authorization_and_lifecycle_models(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-storage-policy-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(["python3", str(GENERATE_AUTH), "--output-dir", str(temp_dir)], check=True)
            subprocess.run(["python3", str(GENERATE_LIFECYCLE), "--output-dir", str(temp_dir)], check=True)

            auth = json.loads((temp_dir / "storage-authorization-model.json").read_text(encoding="utf-8"))
            lifecycle = json.loads((temp_dir / "vdisk-lifecycle-model.json").read_text(encoding="utf-8"))
            actors = {row["actor"]: row for row in auth["actors"]}

            self.assertEqual(auth["storage_authorization_schema_version"], 1)
            self.assertEqual(actors["tenant"]["ownership_scope"], "owned-only")
            self.assertEqual(lifecycle["states"][0]["state"], "PROVISIONED")

    def test_detects_attach_detach_audit_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-storage-audit-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            inventory = temp_dir / "inventory.json"
            audit = temp_dir / "audit.json"
            output = temp_dir / "report.json"
            self.write_json(
                inventory,
                {
                    "pools": [{"pool_id": 1, "capacity_bytes": 8192, "allocated_bytes": 1024, "vdisk_count": 1}],
                    "vdisks": [
                        {
                            "vdisk_id": 31,
                            "pool_id": 1,
                            "owner_partition_id": 7001,
                            "attached_partition_id": 0,
                            "size_bytes": 1024,
                        }
                    ],
                },
            )
            self.write_json(
                audit,
                {
                    "events": [
                        {
                            "target_id": 31,
                            "related_id": 7009,
                            "requester_partition_id": 7001,
                            "operation": "FBVBS_STORAGE_AUDIT_OP_ATTACH_VDISK",
                            "status": 0,
                        }
                    ]
                },
            )
            result = subprocess.run(
                [
                    "python3",
                    str(VERIFY_AUDIT),
                    "--inventory",
                    str(inventory),
                    "--audit-events",
                    str(audit),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["violation_count"], 1)
            self.assertEqual(payload["findings"][0]["kind"], "missing-detach-audit")

    def test_issue_verify_confirmation_and_generate_evidence_trail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-storage-confirm-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            inventory = temp_dir / "inventory.json"
            audit = temp_dir / "audit.json"
            audit_report = temp_dir / "audit-report.json"
            origin = temp_dir / "origin.json"
            confirmation = temp_dir / "confirmation.json"
            output_dir = temp_dir / "trail"

            self.write_json(
                inventory,
                {
                    "pools": [{"pool_id": 5, "capacity_bytes": 8192, "allocated_bytes": 0, "vdisk_count": 0}],
                    "vdisks": [
                        {
                            "vdisk_id": 77,
                            "pool_id": 5,
                            "owner_partition_id": 7001,
                            "attached_partition_id": 0,
                            "size_bytes": 1024,
                        }
                    ],
                },
            )
            self.write_json(audit, {"events": []})
            subprocess.run(
                [
                    "python3",
                    str(VERIFY_AUDIT),
                    "--inventory",
                    str(inventory),
                    "--audit-events",
                    str(audit),
                    "--output",
                    str(audit_report),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(ISSUE_ORIGIN),
                    "--call",
                    "FBVBS_CALL_STORAGE_DESTROY_VDISK",
                    "--operator-id",
                    "alice",
                    "--operator-role",
                    "storage-admin",
                    "--session-correlation-id",
                    "sess-storage-001",
                    "--origin-transport",
                    "host-cli",
                    "--origin-console",
                    "operator-shell",
                    "--host-callsite",
                    "FBVBS_HOST_CALLSITE_FBVBS_PRIMARY",
                    "--output",
                    str(origin),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(ISSUE_CONFIRM),
                    "--operation",
                    "destroy-vdisk",
                    "--target-id",
                    "77",
                    "--operator-id",
                    "alice",
                    "--operator-role",
                    "storage-admin",
                    "--session-correlation-id",
                    "sess-storage-001",
                    "--inventory",
                    str(inventory),
                    "--origin-attestation",
                    str(origin),
                    "--justification",
                    "cleanup unused vdisk",
                    "--output",
                    str(confirmation),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(VERIFY_CONFIRM),
                    "--input",
                    str(confirmation),
                    "--operation",
                    "destroy-vdisk",
                    "--session-correlation-id",
                    "sess-storage-001",
                ],
                check=True,
            )
            result = subprocess.run(
                [
                    "python3",
                    str(GENERATE_TRAIL),
                    "--inventory",
                    str(inventory),
                    "--audit-report",
                    str(audit_report),
                    "--confirmation",
                    str(confirmation),
                    "--output-dir",
                    str(output_dir),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            payload = json.loads((output_dir / "storage-evidence-trail.json").read_text(encoding="utf-8"))
            trails = {row["vdisk_id"]: row for row in payload["vdisk_trails"]}
            self.assertEqual(trails[77]["destructive_confirmation_sha384"], json.loads(confirmation.read_text(encoding="utf-8"))["storage_confirmation_sha384"])
            self.assertEqual(payload["warning_count"], 1)


if __name__ == "__main__":
    unittest.main()
