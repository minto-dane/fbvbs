#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


GENERATE_POLICY = pathlib.Path(__file__).resolve().parents[3] / "tools" / "service" / "generate_service_plane_policy.py"
ISSUE_ATTEST = pathlib.Path(__file__).resolve().parents[3] / "tools" / "security" / "issue_service_identity_attestation.py"
VERIFY_ATTEST = pathlib.Path(__file__).resolve().parents[3] / "tools" / "security" / "verify_service_identity_attestation.py"
RECORD_LIFECYCLE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "service" / "record_service_lifecycle_audit.py"
VERIFY_LIFECYCLE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "service" / "verify_service_lifecycle_audit.py"
GENERATE_SURFACE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "service" / "generate_service_api_surface_minimization.py"


class ServicePlaneSecurityToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_generates_service_plane_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-service-plane-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(["python3", str(GENERATE_POLICY), "--output-dir", str(temp_dir)], check=True)
            payload = json.loads((temp_dir / "service-plane-policy.json").read_text(encoding="utf-8"))
            rows = {row["service_profile"]: row for row in payload["service_profiles"]}

            self.assertEqual(payload["service_policy_schema_version"], 1)
            self.assertFalse(rows["storage-control"]["access_policy"]["default_break_glass_bypass_allowed"])
            self.assertIn("audit-collection", rows["diagnostics"]["peer_policy"]["allowed_peer_profiles"])
            self.assertEqual(
                rows["attestation"]["service_kind_choices"][0]["name"],
                "SERVICE_KIND_UVS",
            )

    def test_issue_and_verify_service_identity_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-service-attest-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            attestation = temp_dir / "service-identity.json"
            subprocess.run(
                [
                    "python3",
                    str(ISSUE_ATTEST),
                    "--service-profile",
                    "attestation",
                    "--service-instance-id",
                    "svc-uvs-001",
                    "--session-correlation-id",
                    "sess-svc-001",
                    "--partition-id",
                    "7001",
                    "--service-kind",
                    "SERVICE_KIND_UVS",
                    "--image-digest-sha384",
                    "a" * 96,
                    "--signer-identity",
                    "CN=UVS Service",
                    "--output",
                    str(attestation),
                ],
                check=True,
            )
            payload = json.loads(attestation.read_text(encoding="utf-8"))
            self.assertEqual(payload["service_profile"], "attestation")
            self.assertEqual(payload["service_kind"]["name"], "SERVICE_KIND_UVS")

            subprocess.run(
                [
                    "python3",
                    str(VERIFY_ATTEST),
                    "--input",
                    str(attestation),
                    "--service-profile",
                    "attestation",
                    "--session-correlation-id",
                    "sess-svc-001",
                ],
                check=True,
            )

    def test_records_and_verifies_service_lifecycle_audit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-service-ledger-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            attestation = temp_dir / "service-identity.json"
            ledger = temp_dir / "service-lifecycle.json"
            subprocess.run(
                [
                    "python3",
                    str(ISSUE_ATTEST),
                    "--service-profile",
                    "diagnostics",
                    "--service-instance-id",
                    "svc-diag-001",
                    "--session-correlation-id",
                    "sess-svc-002",
                    "--partition-id",
                    "7002",
                    "--image-digest-sha384",
                    "b" * 96,
                    "--signer-identity",
                    "CN=Diag Service",
                    "--output",
                    str(attestation),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(RECORD_LIFECYCLE),
                    "--attestation",
                    str(attestation),
                    "--event",
                    "boot",
                    "--detail",
                    "instantiate",
                    "--output",
                    str(ledger),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(RECORD_LIFECYCLE),
                    "--attestation",
                    str(attestation),
                    "--event",
                    "rotate",
                    "--detail",
                    "credential-rotate",
                    "--previous-ledger",
                    str(ledger),
                    "--output",
                    str(ledger),
                ],
                check=True,
            )
            payload = json.loads(ledger.read_text(encoding="utf-8"))
            self.assertEqual(payload["event_count"], 2)
            self.assertEqual(payload["events"][1]["previous_event_sha384"], payload["events"][0]["event_sha384"])

            subprocess.run(
                [
                    "python3",
                    str(VERIFY_LIFECYCLE),
                    "--input",
                    str(ledger),
                    "--service-profile",
                    "diagnostics",
                    "--session-correlation-id",
                    "sess-svc-002",
                ],
                check=True,
            )

    def test_detects_service_api_surface_violation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-service-surface-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            observed = temp_dir / "observed.json"
            self.write_json(
                observed,
                {
                    "services": [
                        {
                            "service_profile": "diagnostics",
                            "service_instance_id": "svc-diag-002",
                            "observed_calls": [
                                "FBVBS_CALL_DIAG_GET_INVENTORY",
                                "FBVBS_CALL_STORAGE_CREATE_POOL",
                            ],
                        }
                    ]
                },
            )
            result = subprocess.run(
                [
                    "python3",
                    str(GENERATE_SURFACE),
                    "--output-dir",
                    str(temp_dir),
                    "--observed",
                    str(observed),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            payload = json.loads(
                (temp_dir / "service-api-surface-minimization.json").read_text(encoding="utf-8")
            )
            self.assertEqual(payload["noncompliant_count"], 1)
            self.assertEqual(
                payload["findings"][0]["unexpected_calls"],
                ["FBVBS_CALL_STORAGE_CREATE_POOL"],
            )


if __name__ == "__main__":
    unittest.main()
