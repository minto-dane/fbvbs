from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HYPERVISOR_DIR = REPO_ROOT / "hypervisor"


class HypervisorImplementationTests(unittest.TestCase):
    def test_c_leaf_build_passes_compiler_static_analysis(self) -> None:
        result = subprocess.run(
            ["make", "-C", str(HYPERVISOR_DIR), "analyze"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stdout + "\n" + result.stderr)

    def test_ada_main_builds_and_runs_with_gprbuild(self) -> None:
        result = subprocess.run(
            ["gprbuild", "-P", "fbvbs_hypervisor.gpr"],
            cwd=HYPERVISOR_DIR / "ada",
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stdout + "\n" + result.stderr)

        result = subprocess.run(
            ["./fbvbs_hypervisor_main"],
            cwd=HYPERVISOR_DIR / "ada",
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stdout + "\n" + result.stderr)

    def test_ada_main_builds_and_runs_with_alire(self) -> None:
        if shutil.which("alr") is None:
            self.skipTest("alr is not installed")

        result = subprocess.run(
            ["alr", "build"],
            cwd=HYPERVISOR_DIR / "ada",
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stdout + "\n" + result.stderr)

        result = subprocess.run(
            ["./fbvbs_hypervisor_main"],
            cwd=HYPERVISOR_DIR / "ada",
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stdout + "\n" + result.stderr)

    def test_ada_dispatcher_models_vm_map_and_tier_b_rules(self) -> None:
        source = HYPERVISOR_DIR / "ada" / "src" / "fbvbs_hypervisor_main.adb"
        content = source.read_text(encoding="utf-8")

        self.assertIn("Dispatch_Request.Observed_RIP := FBVBS.ABI.Host_Callsite_VMM_Primary;", content)
        self.assertIn("Dispatch_Request.Memory_Object_Id := 16#8800#;", content)
        self.assertIn("Dispatch_Request.Guest_Physical_Address := 16#3000#;", content)
        self.assertIn("Dispatch_Request.Protection_Class := FBVBS.ABI.KSI_Class_UCRED;", content)
        self.assertIn("Dispatch_Request.Caller_Ucred_Object_Id := Dispatch_Ucred_Object_Id;", content)
        self.assertIn("Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Modify_Tier_B;", content)
        self.assertIn("Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Allocate_Ucred;", content)
        self.assertIn("Dispatch_Request.Call_Id := FBVBS.ABI.Call_KSI_Unregister_Object;", content)

    def test_ada_packages_expose_vm_map_and_tier_b_specific_validation(self) -> None:
        abi_body = (HYPERVISOR_DIR / "ada" / "src" / "fbvbs-abi.ads").read_text(encoding="utf-8")
        memory_body = (HYPERVISOR_DIR / "ada" / "src" / "fbvbs-memory.adb").read_text(encoding="utf-8")
        dispatcher_body = (HYPERVISOR_DIR / "ada" / "src" / "fbvbs-hypercall_dispatcher.adb").read_text(encoding="utf-8")
        ksi_body = (HYPERVISOR_DIR / "ada" / "src" / "fbvbs-ksi.adb").read_text(encoding="utf-8")

        self.assertIn("type Hash_Buffer", abi_body)
        self.assertIn("Caller_Ucred_Object_Id", abi_body)
        self.assertIn("Measured_Hash", abi_body)
        self.assertIn("Call_KSI_Modify_Tier_B", abi_body)
        self.assertIn("Call_KSI_Allocate_Ucred", abi_body)
        self.assertIn("Call_KSI_Unregister_Object", abi_body)
        self.assertIn("procedure Map_VM_Object", memory_body)
        self.assertIn("Partition.Kind /= FBVBS.ABI.Partition_Guest_VM", memory_body)
        self.assertIn("when FBVBS.ABI.Call_VM_Map_Memory =>", dispatcher_body)
        self.assertIn("when FBVBS.ABI.Call_KSI_Register_Tier_B =>", dispatcher_body)
        self.assertIn("when FBVBS.ABI.Call_KSI_Modify_Tier_B =>", dispatcher_body)
        self.assertIn("Caller_Ucred_Object_Id => Request.Caller_Ucred_Object_Id", dispatcher_body)
        self.assertIn("when FBVBS.ABI.Call_KSI_Allocate_Ucred =>", dispatcher_body)
        self.assertIn("when FBVBS.ABI.Call_KSI_Unregister_Object =>", dispatcher_body)
        self.assertIn("Required_Class := FBVBS.ABI.Host_Caller_VMM;", dispatcher_body)
        self.assertIn("function Valid_Protection_Class", ksi_body)
        self.assertIn("function Hash_Tail_Zero", ksi_body)
        self.assertIn("function Hash_Has_Payload", ksi_body)
        self.assertIn("procedure Register_Tier_B_Object", ksi_body)
        self.assertIn("procedure Modify_Tier_B_Object", ksi_body)
        self.assertIn("procedure Allocate_Ucred", ksi_body)
        self.assertIn("procedure Unregister_Object", ksi_body)

        result = subprocess.run(
            ["./fbvbs_hypervisor_main"],
            cwd=HYPERVISOR_DIR / "ada",
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(result.stdout + "\n" + result.stderr)


if __name__ == "__main__":
    unittest.main()
