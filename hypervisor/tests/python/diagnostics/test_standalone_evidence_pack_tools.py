#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest


EXPORT_DIAG = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "export_diagnostic_bundle.py"
CORRELATE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "correlate_standalone_incident_artifacts.py"
GENERATE_PACK = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "generate_standalone_evidence_pack.py"
ISSUE_ORIGIN = pathlib.Path(__file__).resolve().parents[3] / "tools" / "security" / "issue_command_origin_attestation.py"
RECORD_BREAK_GLASS = pathlib.Path(__file__).resolve().parents[3] / "tools" / "audit" / "record_break_glass_audit.py"


class StandaloneEvidencePackToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_diag_inputs(self, temp_dir: pathlib.Path) -> dict[str, pathlib.Path]:
        schema = temp_dir / "schema.json"
        inventory = temp_dir / "inventory.json"
        partition_list = temp_dir / "partition-list.json"
        guidance = temp_dir / "guidance.json"
        fault_record = temp_dir / "fault-record.json"

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
        self.write_json(
            inventory,
            {
                "occupied_partition_count": 2,
                "quarantined_partition_count": 1,
                "recovery_partition_count": 0,
            },
        )
        self.write_json(
            partition_list,
            {
                "count": 2,
                "entries": [
                    {"partition_id": 4097, "health_state": 2, "fault_code": 77, "quarantine_reason": 77},
                    {"partition_id": 4098, "health_state": 1, "fault_code": 0, "quarantine_reason": 0},
                ],
            },
        )
        self.write_json(guidance, {"partition_id": 4098, "reason_domain": 4, "severity": 3, "runbook_code": 7})
        self.write_json(fault_record, {"partition_id": 4097, "severity": 6, "fault_code": 77})
        return {
            "schema": schema,
            "inventory": inventory,
            "partition_list": partition_list,
            "guidance": guidance,
            "fault_record": fault_record,
        }

    def make_operator_artifacts(self, temp_dir: pathlib.Path) -> dict[str, pathlib.Path]:
        timeline = temp_dir / "timeline-sealed.json"
        severity = temp_dir / "operator-console-severity-summary.json"
        ack = temp_dir / "ack-ledger.json"
        approval = temp_dir / "recovery-approval.json"
        origin = temp_dir / "origin-attestation.json"
        break_glass = temp_dir / "break-glass-ledger.json"
        matrix = temp_dir / "operator-tooling-compatibility-matrix.json"
        panel = temp_dir / "ocs-panel-manifest.json"

        self.write_json(
            timeline,
            {
                "audit_schema_version": 1,
                "root_chain_sha384": "a" * 96,
                "record_count": 2,
                "input_files": ["audit.log"],
                "boot_sessions": [
                    {"boot_id": "global", "record_count": 2, "gap_count": 1},
                ],
            },
        )
        self.write_json(
            severity,
            {
                "presentation_locale": "ja",
                "overall_severity": {"name": "ALERT", "value": 6},
                "partitions": [
                    {
                        "partition_id": 4097,
                        "health_state": {"name": "QUARANTINED", "value": 2},
                        "fault_code": 77,
                        "quarantine_reason": 77,
                        "severity": {"name": "ALERT", "value": 6, "source": "fault-record"},
                    },
                    {
                        "partition_id": 4098,
                        "health_state": {"name": "DEGRADED", "value": 1},
                        "fault_code": 0,
                        "quarantine_reason": 0,
                        "severity": {"name": "WARNING", "value": 3, "source": "guidance"},
                    },
                ],
            },
        )
        self.write_json(
            ack,
            {
                "timeline_root_chain_sha384": "a" * 96,
                "session_correlation_id": "sess-pack-001",
                "acknowledgment_count": 1,
                "latest_ack_sha384": "b" * 96,
                "acknowledgments": [
                    {
                        "ack_sequence": 1,
                        "operator_id": "alice",
                        "session_correlation_id": "sess-pack-001",
                        "ack_sha384": "b" * 96,
                    }
                ],
            },
        )
        self.write_json(
            approval,
            {
                "action": "recover-approved",
                "partition_id": 4097,
                "timeline_root_chain_sha384": "a" * 96,
                "session_correlation_id": "sess-pack-001",
            },
        )
        subprocess.run(
            [
                "python3",
                str(ISSUE_ORIGIN),
                "--call",
                "FBVBS_CALL_PARTITION_RECOVER",
                "--operator-id",
                "alice",
                "--operator-role",
                "incident-responder",
                "--session-correlation-id",
                "sess-pack-001",
                "--origin-transport",
                "ocs-vcd",
                "--origin-console",
                "mainframe-tui",
                "--host-callsite",
                "FBVBS_HOST_CALLSITE_FBVBS_PRIMARY",
                "--partition-id",
                "4097",
                "--timeline-root-sha384",
                "a" * 96,
                "--break-glass",
                "--justification",
                "sev1-pack",
                "--output",
                str(origin),
            ],
            check=True,
        )
        subprocess.run(
            [
                "python3",
                str(RECORD_BREAK_GLASS),
                "--origin-attestation",
                str(origin),
                "--timeline-seal",
                str(timeline),
                "--severity-summary",
                str(severity),
                "--ack-ledger",
                str(ack),
                "--ticket-id",
                "INC-9002",
                "--operator-id",
                "alice",
                "--output",
                str(break_glass),
            ],
            check=True,
        )
        self.write_json(
            matrix,
            {
                "summary": {"row_count": 12},
                "schema_registry": {"management_abi_version": 1},
            },
        )
        self.write_json(
            panel,
            {
                "style": "mainframe-ispf-inspired",
                "presentation_locale": "ja",
            },
        )
        return {
            "timeline": timeline,
            "severity": severity,
            "ack": ack,
            "approval": approval,
            "origin": origin,
            "break_glass": break_glass,
            "matrix": matrix,
            "panel": panel,
        }

    def make_diagnostic_bundle(self, temp_dir: pathlib.Path) -> pathlib.Path:
        inputs = self.make_diag_inputs(temp_dir)
        output = temp_dir / "diagnostic-bundle.tar.gz"
        subprocess.run(
            [
                "python3",
                str(EXPORT_DIAG),
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
            ],
            check=True,
        )
        return output

    def test_correlation_tool_generates_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-correlation-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            diag_bundle = self.make_diagnostic_bundle(temp_dir)
            artifacts = self.make_operator_artifacts(temp_dir)

            subprocess.run(
                [
                    "python3",
                    str(CORRELATE),
                    "--diagnostic-bundle",
                    str(diag_bundle),
                    "--timeline",
                    str(artifacts["timeline"]),
                    "--severity-summary",
                    str(artifacts["severity"]),
                    "--ack-ledger",
                    str(artifacts["ack"]),
                    "--recovery-approval",
                    str(artifacts["approval"]),
                    "--origin-attestation",
                    str(artifacts["origin"]),
                    "--break-glass-ledger",
                    str(artifacts["break_glass"]),
                    "--compatibility-matrix",
                    str(artifacts["matrix"]),
                    "--panel-manifest",
                    str(artifacts["panel"]),
                    "--locale",
                    "ja",
                    "--output-dir",
                    str(temp_dir),
                ],
                check=True,
            )

            json_path = temp_dir / "standalone-evidence-correlation.json"
            md_path = temp_dir / "standalone-evidence-correlation.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
            self.assertEqual(payload["correlation_schema_version"], 1)
            self.assertEqual(payload["operator_acknowledgment"]["acknowledgment_count"], 1)
            self.assertEqual(payload["operator_acknowledgment"]["session_correlation_id"], "sess-pack-001")
            self.assertEqual(payload["recovery_approval"]["session_correlation_id"], "sess-pack-001")
            self.assertEqual(payload["origin_attestation"]["session_correlation_id"], "sess-pack-001")
            self.assertTrue(payload["origin_attestation"]["break_glass"])
            self.assertEqual(payload["break_glass"]["audit_channel"], "operator-break-glass")
            self.assertEqual(payload["session_correlation"]["session_correlation_ids"], ["sess-pack-001"])
            self.assertEqual(payload["timeline"]["gap_count_total"], 1)
            self.assertEqual(payload["schema_versions"]["timeline_audit_schema_version"], 1)
            self.assertEqual(payload["compatibility_matrix"]["row_count"], 12)
            self.assertEqual(payload["panel_manifest"]["style"], "mainframe-ispf-inspired")
            self.assertIn("timeline contains sequence gaps", payload["warnings"])
            self.assertIn("スタンドアロン証跡 相関サマリー", markdown)

    def test_evidence_pack_can_be_signed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-evidence-pack-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            diag_bundle = self.make_diagnostic_bundle(temp_dir)
            artifacts = self.make_operator_artifacts(temp_dir)
            output = temp_dir / "standalone-evidence-pack.tar.gz"
            key = temp_dir / "signing-key.pem"
            cert = temp_dir / "signing-cert.pem"
            pubkey = temp_dir / "signing-pubkey.pem"

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
                    "/CN=FBVBS Standalone Evidence Pack Test",
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
                    str(GENERATE_PACK),
                    "--output",
                    str(output),
                    "--allow-input-root",
                    str(temp_dir),
                    "--diagnostic-bundle",
                    str(diag_bundle),
                    "--timeline",
                    str(artifacts["timeline"]),
                    "--severity-summary",
                    str(artifacts["severity"]),
                    "--ack-ledger",
                    str(artifacts["ack"]),
                    "--recovery-approval",
                    str(artifacts["approval"]),
                    "--origin-attestation",
                    str(artifacts["origin"]),
                    "--break-glass-ledger",
                    str(artifacts["break_glass"]),
                    "--compatibility-matrix",
                    str(artifacts["matrix"]),
                    "--panel-manifest",
                    str(artifacts["panel"]),
                    "--signing-key",
                    str(key),
                    "--signing-cert",
                    str(cert),
                    "--capture-complete",
                    "--locale",
                    "ja",
                    "--note",
                    "unit-test-pack",
                ],
                check=True,
            )

            with tarfile.open(output, "r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("evidence/standalone-evidence-pack-manifest.json", names)
                self.assertIn("evidence/standalone-evidence-pack-manifest.sig", names)
                self.assertIn("evidence/standalone-evidence-correlation.json", names)
                self.assertIn("evidence/standalone-state-manifest.json", names)
                self.assertIn("evidence/recovery-approval.json", names)
                self.assertIn("evidence/origin-attestation.json", names)
                self.assertIn("evidence/break-glass-ledger.json", names)
                self.assertIn("docs/standalone-evidence-correlation.md", names)
                self.assertIn("evidence/diagnostic-bundle.tar.gz", names)
                manifest = json.load(
                    archive.extractfile("evidence/standalone-evidence-pack-manifest.json")
                )
                state_manifest = json.load(
                    archive.extractfile("evidence/standalone-state-manifest.json")
                )
            self.assertTrue(manifest["signed"])
            self.assertTrue(manifest["capture_complete"])
            self.assertEqual(manifest["session_correlation_id"], "sess-pack-001")
            self.assertEqual(manifest["correlation_summary"]["operator_acknowledgment"]["acknowledgment_count"], 1)
            self.assertEqual(manifest["correlation_summary"]["origin_attestation"]["call_name"], "FBVBS_CALL_PARTITION_RECOVER")
            self.assertEqual(manifest["correlation_summary"]["break_glass"]["event_count"], 1)
            self.assertEqual(manifest["signature"]["certificate_path"], "evidence/evidence-pack-signer.pem")
            self.assertEqual(state_manifest["compatibility_windows"]["evidence_pack_format_version"]["current"], 1)
            self.assertEqual(state_manifest["artifact_state"]["origin_attestation_present"], True)
            self.assertEqual(state_manifest["artifact_state"]["break_glass_ledger_present"], True)

            with tempfile.TemporaryDirectory(prefix="fbvbs-evidence-verify-") as verify_dir_raw:
                verify_dir = pathlib.Path(verify_dir_raw)
                with tarfile.open(output, "r:gz") as archive:
                    manifest_bytes = archive.extractfile(
                        "evidence/standalone-evidence-pack-manifest.json"
                    ).read()
                    signature_bytes = archive.extractfile(
                        "evidence/standalone-evidence-pack-manifest.sig"
                    ).read()
                (verify_dir / "evidence").mkdir()
                (verify_dir / "evidence" / "standalone-evidence-pack-manifest.json").write_bytes(
                    manifest_bytes
                )
                (verify_dir / "evidence" / "standalone-evidence-pack-manifest.sig").write_bytes(
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
                        str(verify_dir / "evidence/standalone-evidence-pack-manifest.sig"),
                        str(verify_dir / "evidence/standalone-evidence-pack-manifest.json"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )


if __name__ == "__main__":
    unittest.main()
