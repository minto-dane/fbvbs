#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "export_diagnostic_bundle.py"


class DiagnosticBundleToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_inputs(self, temp_dir: pathlib.Path) -> dict[str, pathlib.Path]:
        schema = temp_dir / "schema.json"
        inventory = temp_dir / "inventory.json"
        partition_list = temp_dir / "partition-list.json"
        guidance = temp_dir / "guidance.json"
        fault_record = temp_dir / "fault-record.json"
        doc = temp_dir / "diag-doc.md"

        self.write_json(
            schema,
            {
                "management_abi_version": 1,
                "health_schema_version": 1,
                "audit_schema_version": 1,
                "inventory_schema_version": 1,
                "guidance_schema_version": 1,
                "fault_record_schema_version": 1,
                "compatibility_flags": 15,
            },
        )
        self.write_json(inventory, {"occupied_partition_count": 1, "quarantined_partition_count": 1})
        self.write_json(partition_list, {"count": 1, "entries": [{"partition_id": 4096}]})
        self.write_json(guidance, {"reason_domain": 4, "runbook_code": 5})
        self.write_json(fault_record, {"partition_id": 4096, "fault_code": 5})
        doc.write_text("# diag\n", encoding="utf-8")

        return {
            "schema": schema,
            "inventory": inventory,
            "partition_list": partition_list,
            "guidance": guidance,
            "fault_record": fault_record,
            "doc": doc,
        }

    def test_exports_unsigned_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-test-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            inputs = self.make_inputs(temp_dir)

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--guidance",
                    str(inputs["guidance"]),
                    "--fault-record",
                    str(inputs["fault_record"]),
                    "--doc",
                    str(inputs["doc"]),
                    "--note",
                    "unit-test",
                ],
                check=True,
            )

            self.assertTrue(output.is_file())
            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("diagnostics/diagnostic-bundle-manifest.json", names)
                self.assertIn("diagnostics/schema-registry.json", names)
                self.assertIn("diagnostics/inventory.json", names)
                self.assertIn("diagnostics/partition-list.json", names)
                self.assertIn("diagnostics/fault-record-00.json", names)
                self.assertIn("diagnostics/guidance-00.json", names)
                self.assertIn("docs/diag-doc.md", names)
                manifest = json.load(
                    archive.extractfile("diagnostics/diagnostic-bundle-manifest.json")
                )
            self.assertFalse(manifest["signed"])
            self.assertEqual(manifest["bundle_format_version"], 2)
            self.assertFalse(manifest["capture_complete"])
            self.assertEqual(len(manifest["collection_warnings"]), 1)
            self.assertEqual(manifest["fault_record_count"], 1)
            self.assertEqual(manifest["guidance_count"], 1)
            self.assertEqual(
                manifest["artifacts"][0]["archive_path"],
                "diagnostics/schema-registry.json",
            )
            self.assertEqual(manifest["artifacts"][0]["source_root_index"], 1)
            self.assertEqual(
                manifest["artifacts"][0]["source_path"],
                "schema.json",
            )
            self.assertFalse(manifest["signature"]["signed"])

    def test_exports_signed_bundle_when_key_is_supplied(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-sign-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            key = temp_dir / "signing-key.pem"
            cert = temp_dir / "signing-cert.pem"
            pubkey = temp_dir / "signing-pubkey.pem"
            inputs = self.make_inputs(temp_dir)

            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    str(key),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(key),
                    "-subj",
                    "/CN=FBVBS Diagnostic Bundle Test",
                    "-days",
                    "1",
                    "-out",
                    str(cert),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--signing-key",
                    str(key),
                    "--signing-cert",
                    str(cert),
                ],
                check=True,
            )

            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("diagnostics/diagnostic-bundle-manifest.sig", names)
                self.assertIn("diagnostics/diagnostic-bundle-signer.pem", names)
                manifest = json.load(
                    archive.extractfile("diagnostics/diagnostic-bundle-manifest.json")
                )
            self.assertTrue(manifest["signed"])
            self.assertFalse(manifest["capture_complete"])
            self.assertEqual(
                manifest["signature"]["signature_path"],
                "diagnostics/diagnostic-bundle-manifest.sig",
            )
            self.assertIsNotNone(manifest["signature"]["public_key_fingerprint_sha384"])
            self.assertIsNotNone(manifest["signature"]["certificate_fingerprint_sha384"])
            self.assertIsNotNone(manifest["signature"]["verification_hint"])
            self.assertEqual(manifest["artifacts"][-1]["kind"], "signing-certificate")

            with tempfile.TemporaryDirectory(prefix="fbvbs-diag-verify-") as verify_dir_raw:
                verify_dir = pathlib.Path(verify_dir_raw)
                with tarfile.open(output, "r:gz") as archive:
                    manifest_bytes = archive.extractfile(
                        "diagnostics/diagnostic-bundle-manifest.json"
                    ).read()
                    signature_bytes = archive.extractfile(
                        "diagnostics/diagnostic-bundle-manifest.sig"
                    ).read()
                (verify_dir / "diagnostics").mkdir()
                (verify_dir / "diagnostics" / "diagnostic-bundle-manifest.json").write_bytes(
                    manifest_bytes
                )
                (verify_dir / "diagnostics" / "diagnostic-bundle-manifest.sig").write_bytes(
                    signature_bytes
                )
                subprocess.run(
                    [
                        "openssl",
                        "pkey",
                        "-in",
                        str(key),
                        "-pubout",
                        "-out",
                        str(pubkey),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                subprocess.run(
                    [
                        "openssl",
                        "dgst",
                        "-sha384",
                        "-verify",
                        str(pubkey),
                        "-signature",
                        str(verify_dir / "diagnostics/diagnostic-bundle-manifest.sig"),
                        str(verify_dir / "diagnostics/diagnostic-bundle-manifest.json"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

    def test_rejects_external_input_without_allow_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-reject-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            inputs = self.make_inputs(temp_dir)

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside allowed roots", result.stderr)

    def test_marks_manifest_complete_only_when_explicitly_requested(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-complete-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            inputs = self.make_inputs(temp_dir)

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--capture-complete",
                ],
                check=True,
            )

            with tarfile.open(output, "r:gz") as archive:
                manifest = json.load(
                    archive.extractfile("diagnostics/diagnostic-bundle-manifest.json")
                )
            self.assertTrue(manifest["capture_complete"])
            self.assertEqual(manifest["collection_warnings"], [])

    def test_rejects_private_key_in_include_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-secret-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            inputs = self.make_inputs(temp_dir)
            secret_file = temp_dir / "operator.key"
            secret_file.write_text(
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--include",
                    str(secret_file),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to include", result.stderr)

    def test_bundles_scrubbed_support_dump_with_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-support-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            inputs = self.make_inputs(temp_dir)
            support_dump = temp_dir / "scrubbed-00-support.log"
            scrub_report = temp_dir / "support-dump-scrub-report.json"

            support_dump.write_text(
                "Authorization: Bearer <REDACTED:BEARER_TOKEN>\n",
                encoding="utf-8",
            )
            self.write_json(
                scrub_report,
                {
                    "tool": {
                        "name": "scrub_support_dump.py",
                        "version": 1,
                    },
                    "artifact_count": 1,
                    "artifacts": [
                        {
                            "source_path": "support.log",
                            "output_path": support_dump.name,
                            "redaction_count": 1,
                            "triggered_rules": ["bearer_token"],
                        }
                    ],
                },
            )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--support-dump",
                    str(support_dump),
                    "--support-dump-report",
                    str(scrub_report),
                ],
                check=True,
            )

            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("diagnostics/support-dump-00-scrubbed-00-support.log", names)
                self.assertIn("diagnostics/support-dump-scrub-report.json", names)
                manifest = json.load(
                    archive.extractfile("diagnostics/diagnostic-bundle-manifest.json")
                )
            self.assertEqual(manifest["support_dump_count"], 1)
            self.assertEqual(manifest["support_dump_report_count"], 1)
            self.assertTrue(manifest["support_dump_scrubbing"]["scrubbed"])
            self.assertEqual(
                manifest["support_dump_scrubbing"]["report_archive_path"],
                "diagnostics/support-dump-scrub-report.json",
            )

    def test_requires_scrub_report_for_support_dump(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-support-fail-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            inputs = self.make_inputs(temp_dir)
            support_dump = temp_dir / "scrubbed-00-support.log"

            support_dump.write_text("safe output\n", encoding="utf-8")

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--support-dump",
                    str(support_dump),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("require --support-dump-report", result.stderr)

    def test_rejects_support_dump_report_count_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-diag-support-count-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "diagnostic-bundle.tar.gz"
            inputs = self.make_inputs(temp_dir)
            support_dump = temp_dir / "scrubbed-00-support.log"
            scrub_report = temp_dir / "support-dump-scrub-report.json"

            support_dump.write_text("safe output\n", encoding="utf-8")
            self.write_json(
                scrub_report,
                {
                    "tool": {
                        "name": "scrub_support_dump.py",
                        "version": 1,
                    },
                    "artifact_count": 2,
                    "artifacts": [
                        {
                            "source_path": "support.log",
                            "output_path": support_dump.name,
                            "redaction_count": 0,
                            "triggered_rules": [],
                        }
                    ],
                },
            )

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--support-dump",
                    str(support_dump),
                    "--support-dump-report",
                    str(scrub_report),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifact_count does not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
