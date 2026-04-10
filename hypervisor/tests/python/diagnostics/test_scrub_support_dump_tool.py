#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest
import zipfile
import gzip


SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "scrub_support_dump.py"


class ScrubSupportDumpToolTests(unittest.TestCase):
    def test_scrubs_secret_like_text_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-scrub-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "support.log"
            output_dir = temp_dir / "scrubbed"
            input_path.write_text(
                "\n".join(
                    [
                        "Authorization: Bearer supersecrettokenvalue",
                        "x-api-key: abcdefghijklmnop",
                        "aws_secret_access_key = abcdefghijklmnopqrstuvwx0123456789AB",
                        "password = hunter2",
                        "-----BEGIN PRIVATE KEY-----",
                        "MIIB",
                        "-----END PRIVATE KEY-----",
                        "safe_line = keep_me",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output-dir",
                    str(output_dir),
                    "--allow-input-root",
                    str(temp_dir),
                    "--input",
                    str(input_path),
                ],
                check=True,
            )

            scrubbed_path = output_dir / "scrubbed-00-support.log"
            report_path = output_dir / "support-dump-scrub-report.json"
            self.assertTrue(scrubbed_path.is_file())
            self.assertTrue(report_path.is_file())

            scrubbed_text = scrubbed_path.read_text(encoding="utf-8")
            self.assertNotIn("supersecrettokenvalue", scrubbed_text)
            self.assertNotIn("abcdefghijklmnop", scrubbed_text)
            self.assertNotIn("hunter2", scrubbed_text)
            self.assertNotIn("BEGIN PRIVATE KEY", scrubbed_text)
            self.assertIn("<REDACTED:BEARER_TOKEN>", scrubbed_text)
            self.assertIn("<REDACTED:API_KEY>", scrubbed_text)
            self.assertIn("<REDACTED:AWS_SECRET_ACCESS_KEY>", scrubbed_text)
            self.assertIn("<REDACTED:PASSWORD>", scrubbed_text)
            self.assertIn("<REDACTED:PRIVATE_KEY>", scrubbed_text)
            self.assertIn("safe_line = keep_me", scrubbed_text)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["artifact_count"], 1)
            self.assertEqual(report["artifacts"][0]["source_path"], "support.log")
            self.assertEqual(report["artifacts"][0]["format"], "text")
            self.assertGreaterEqual(report["artifacts"][0]["redaction_count"], 5)
            self.assertIn("private_key_block", report["artifacts"][0]["triggered_rules"])

    def test_scrubs_binary_input_in_place(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-scrub-bin-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "support.bin"
            output_dir = temp_dir / "scrubbed"
            input_path.write_bytes(
                b"\x00Authorization: Bearer supersecrettokenvalue\x00password=hunter2\xff"
            )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output-dir",
                    str(output_dir),
                    "--allow-input-root",
                    str(temp_dir),
                    "--input",
                    str(input_path),
                ],
                check=True,
            )

            scrubbed_path = output_dir / "scrubbed-00-support.bin"
            scrubbed = scrubbed_path.read_bytes()
            self.assertNotIn(b"supersecrettokenvalue", scrubbed)
            self.assertNotIn(b"hunter2", scrubbed)
            self.assertIn(b"<REDACTED:BEARER_TOKEN>", scrubbed)
            self.assertIn(b"<REDACTED:PASSWORD>", scrubbed)

            report = json.loads(
                (output_dir / "support-dump-scrub-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["artifacts"][0]["format"], "binary")
            self.assertGreaterEqual(report["artifacts"][0]["redaction_count"], 2)

    def test_scrubs_archive_members_recursively(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-scrub-archive-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "support.zip"
            output_dir = temp_dir / "scrubbed"
            nested_name = "logs/nested.txt.gz"
            with zipfile.ZipFile(input_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "logs/support.log",
                    "Authorization: Bearer supersecrettokenvalue\nsafe_line = keep_me\n",
                )
                archive.writestr(
                    nested_name,
                    subprocess.run(
                        [
                            "python3",
                            "-c",
                            (
                                "import gzip,io,sys;"
                                "buf=io.BytesIO();"
                                "g=gzip.GzipFile(filename='nested.txt',fileobj=buf,mode='wb',mtime=0);"
                                "g.write(b'password = hunter2\\n');"
                                "g.close();"
                                "sys.stdout.buffer.write(buf.getvalue())"
                            ),
                        ],
                        check=True,
                        capture_output=True,
                    ).stdout,
                )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output-dir",
                    str(output_dir),
                    "--allow-input-root",
                    str(temp_dir),
                    "--input",
                    str(input_path),
                ],
                check=True,
            )

            scrubbed_archive = output_dir / "scrubbed-00-support.zip"
            report = json.loads(
                (output_dir / "support-dump-scrub-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["artifacts"][0]["format"], "zip")
            self.assertEqual(report["artifacts"][0]["member_count"], 2)
            with zipfile.ZipFile(scrubbed_archive, "r") as archive:
                scrubbed_text = archive.read("logs/support.log").decode("utf-8")
                nested_payload = archive.read(nested_name)
            self.assertIn("<REDACTED:BEARER_TOKEN>", scrubbed_text)
            self.assertNotIn("supersecrettokenvalue", scrubbed_text)
            self.assertTrue(nested_payload.startswith(b"\x1f\x8b"))
            self.assertNotIn(
                b"hunter2",
                gzip.decompress(nested_payload),
            )


if __name__ == "__main__":
    unittest.main()
