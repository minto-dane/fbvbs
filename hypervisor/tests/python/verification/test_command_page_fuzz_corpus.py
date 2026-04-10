#!/usr/bin/env python3

import pathlib
import struct
import unittest


CORPUS_DIR = pathlib.Path(__file__).resolve().parents[3] / "fuzz" / "corpus" / "command_page"


def load_hex_seed(path: pathlib.Path) -> bytes:
    chunks: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        chunks.append("".join(line.split()))
    return bytes.fromhex("".join(chunks))


def decode_header(data: bytes) -> dict[str, int]:
    padded = data + (b"\x00" * max(0, 56 - len(data)))
    values = struct.unpack("<IHHIIQQIIQQ", padded[:56])
    return {
        "abi_version": values[0],
        "call_id": values[1],
        "flags": values[2],
        "input_length": values[3],
        "output_length_max": values[4],
        "caller_sequence": values[5],
        "caller_nonce": values[6],
        "command_state": values[7],
        "actual_output_length": values[8],
        "output_page_gpa": values[9],
        "reserved0": values[10],
    }


class CommandPageFuzzCorpusTests(unittest.TestCase):
    def test_command_page_corpus_covers_reserved_and_malformed_management_inputs(self) -> None:
        seed_paths = sorted(path for path in CORPUS_DIR.iterdir() if path.is_file())
        self.assertGreaterEqual(len(seed_paths), 10)

        expected = {
            "diag_get_schema_registry_valid.hex",
            "diag_get_schema_registry_page_reserved0.hex",
            "diag_get_schema_registry_reserved_flag.hex",
            "diag_negotiate_command_version_reserved_field.hex",
            "diag_negotiate_command_version_short_output.hex",
            "diag_negotiate_guest_features_exact.hex",
            "diag_negotiate_guest_features_reserved_field.hex",
            "diag_negotiate_guest_features_tail_nonzero.hex",
            "diag_negotiate_guest_features_unsupported_profile.hex",
            "diag_negotiate_guest_features_unsupported_version.hex",
        }
        self.assertTrue(expected.issubset({path.name for path in seed_paths}))

        headers = {
            path.name: decode_header(load_hex_seed(path))
            for path in seed_paths
        }

        guest_exact = headers["diag_negotiate_guest_features_exact.hex"]
        self.assertEqual(guest_exact["call_id"], 0x800D)
        self.assertEqual(guest_exact["input_length"], 16)
        self.assertEqual(guest_exact["command_state"], 1)

        guest_reserved = headers["diag_negotiate_guest_features_reserved_field.hex"]
        self.assertEqual(guest_reserved["call_id"], 0x800D)

        guest_short = headers["diag_negotiate_guest_features_tail_nonzero.hex"]
        self.assertEqual(guest_short["input_length"], 8)

        version_reserved = headers["diag_negotiate_command_version_reserved_field.hex"]
        self.assertEqual(version_reserved["call_id"], 0x800C)
        self.assertEqual(version_reserved["input_length"], 16)

        version_short_output = headers["diag_negotiate_command_version_short_output.hex"]
        self.assertLess(version_short_output["output_length_max"], 16)

        schema_valid = headers["diag_get_schema_registry_valid.hex"]
        self.assertEqual(schema_valid["call_id"], 0x800B)
        self.assertEqual(schema_valid["flags"], 0)
        self.assertEqual(schema_valid["reserved0"], 0)

        schema_reserved0 = headers["diag_get_schema_registry_page_reserved0.hex"]
        self.assertEqual(schema_reserved0["call_id"], 0x800B)
        self.assertNotEqual(schema_reserved0["reserved0"], 0)

        schema_reserved_flag = headers["diag_get_schema_registry_reserved_flag.hex"]
        self.assertEqual(schema_reserved_flag["call_id"], 0x800B)
        self.assertNotEqual(schema_reserved_flag["flags"], 0)


if __name__ == "__main__":
    unittest.main()
