#!/usr/bin/env python3
"""FBVBS Requirement Traceability Matrix Generator (REQ-1000)

Scans source code and test files for REQ-XXXX references, then
cross-references with the roadmap to produce a bidirectional
traceability matrix.

Usage:
    python3 tools/traceability_matrix.py

Output: Markdown table showing requirement → implementation → test links.
"""

import os
import re
import sys
from datetime import date
from collections import defaultdict

HYPERVISOR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(HYPERVISOR_DIR, "src")
INCLUDE_DIR = os.path.join(HYPERVISOR_DIR, "include")
TEST_DIR = os.path.join(HYPERVISOR_DIR, "tests")
FUZZ_DIR = os.path.join(HYPERVISOR_DIR, "fuzz")
COMPLIANCE_DIR = os.path.join(HYPERVISOR_DIR, "compliance")

REQ_PATTERN = re.compile(r"REQ-(\d{4})")

# Requirement descriptions (from design spec)
REQ_NAMES = {
    "0001": "FreeBSD より前にロード",
    "0002": "VMX root 取得",
    "0003": "IOMMU 必須",
    "0004": "ロールバック防止",
    "0005": "一次監査ログ経路",
    "0006": "起動時検証・測定",
    "0100": "一次/ミラー分離",
    "0101": "OOB 経路",
    "0102": "ミラー非根拠",
    "0103": "レコード形式",
    "0104": "CRC のみ不可 (HMAC)",
    "0105": "ミラー read-only (EPT)",
    "0106": "early boot/panic",
    "0107": "リングバッファ形式",
    "0200": "責務限定",
    "0201": "形式的解析証拠",
    "0202": "パーティション状態",
    "0203": "メモリゼロ化",
    "0204": "capability 管理",
    "0205": "hypercall ABI",
    "0206": "未使用領域ゼロ化",
    "0207": "trap レジスタ規約",
    "0208": "ABI version check",
    "0209": "caller_sequence",
    "0210": "command page 状態機械",
    "0211": "lifecycle 遷移限定",
    "0212": "RESUME/RECOVER 分離",
    "0300": "CR ピン留め",
    "0301": "Intel HLAT 必須",
    "0302": "AMD NPT 複合経路",
    "0303": "AMD 高保証実証",
    "0304": "SEV-SNP 補強のみ",
    "0310": "eIBRS/AutoIBRS",
    "0311": "IBPB on context switch",
    "0312": "BHI_DIS_S",
    "0313": "PBRSB 緩和",
    "0314": "AMD STIBP",
    "0315": "RSB fill",
    "0316": "L1TF flush",
    "0317": "VERW/MDS/TAA",
    "0318": "AMD LFENCE serialize",
    "0319": "per-CPU vuln profile",
    "0320": "AMD SRSO/Inception",
    "0321": "Intel GDS check",
    "0330": "CET-SS",
    "0331": "CET MSR per-vCPU",
    "0332": "Shadow Stack EPT",
    "0333": "CET-IBT",
    "0340": "MSR インターセプト",
    "0341": "VPID/ASID",
    "0342": "DR 分離",
    "0343": "RDPMC インターセプト",
    "0344": "Intel PT/AMD IBS",
    "0345": "UMIP",
    "0350": "DMA remapping",
    "0351": "Interrupt remapping",
    "0352": "Passthrough qualification",
    "0353": "外部 DMA 分離",
    "0360": "DRTM",
    "0361": "Boot Guard/PSB",
    "0362": "TPM PCR 検証",
    "0370": "Preemption Timer",
    "0371": "NOTIFY/Bus Lock Exit",
    "0372": "exit/entry シーケンス",
    "0400": "W^X enforcement",
    "0401": "モジュール署名",
    "0402": "翻訳整合性連携",
    "0500": "KSI 基本機能",
    "0501": "Shadow copy",
    "0502": "Reference pointer 制限",
    "0503": "setuid/setgid 検証",
    "0504": "fsid + fileid",
    "0505": "fd 継承リスク",
    "0506": "Callsite 検証 (RIP)",
    "0507": "setuid DB 照合",
    "0508": "許可 callsite table",
    "0600": "IKS 基本機能",
    "0601": "IKS API 制限",
    "0602": "外部暗号 TCB",
    "0603": "SKS ディスク暗号鍵",
    "0604": "KEY_EXCHANGE ハンドル",
    "0700": "UVS 基本機能",
    "0701": "署名付きマニフェスト",
    "0702": "freshness 検出",
    "0703": "HSM + dual-approval",
    "0704": "freeze 攻撃検出",
    "0705": "mix-and-match 防止",
    "0800": "FreeBSD 統合基盤",
    "0801": "非信頼 ABI 変換層",
    "0802": "介入点",
    "0803": "mac(9) 十分性",
    "0804": "vmm(4) boot-time 介入",
    "0900": "bhyve 互換",
    "0901": "libvmmapi 互換",
    "0902": "未分類 exit fail-closed",
    "0903": "再利用前ゼロ化",
    "0904": "IOMMU グループ検証",
    "0905": "live migration/nested 除外",
    "0906": "VM_RUN は Runnable のみ",
    "0907": "vCPU 状態機械",
    "0908": "VM_GET_VCPU_STATUS",
    "0909": "memory object 明示解放",
    "1000": "トレーサビリティ",
    "1001": "TCB 変更独立レビュー",
    "1002": "SPARK 例外不在証明",
    "1003": "Rust TCB 制約",
    "1004": "継続的ファジング",
    "1005": "MC/DC カバレッジ",
    "1006": "再現可能ビルド",
    "1100": "AMD 翻訳整合性実証",
    "1101": "FreeBSD 介入点十分性",
    "1102": "更新メタデータ freshness",
    "1103": "一次ログ経路運用性",
    "1104": "暗号 TCB 確定",
    "1105": "passthrough qualification",
}


def scan_directory(dirpath, extensions=(".c", ".h")):
    """Scan files in directory for REQ references."""
    refs = defaultdict(set)  # req_id -> set of (file, line)
    if not os.path.isdir(dirpath):
        return refs
    for root, dirs, files in os.walk(dirpath):
        dirs.sort()
        for fname in sorted(files):
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            fpath = os.path.join(root, fname)
            relname = os.path.relpath(fpath, dirpath)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        for m in REQ_PATTERN.finditer(line):
                            refs[m.group(1)].add((relname, lineno))
            except OSError:
                pass
    return refs


def main():
    # Scan all directories
    src_refs = scan_directory(SRC_DIR)
    inc_refs = scan_directory(INCLUDE_DIR)
    test_refs = scan_directory(TEST_DIR)
    fuzz_refs = scan_directory(FUZZ_DIR)
    compliance_refs = scan_directory(COMPLIANCE_DIR, extensions=(".md",))

    # Merge source + include
    impl_refs = defaultdict(set)
    for req_id, locs in src_refs.items():
        impl_refs[req_id].update(locs)
    for req_id, locs in inc_refs.items():
        impl_refs[req_id].update(locs)

    # Merge test + fuzz
    verify_refs = defaultdict(set)
    for req_id, locs in test_refs.items():
        verify_refs[req_id].update(locs)
    for req_id, locs in fuzz_refs.items():
        verify_refs[req_id].update(locs)
    for req_id, locs in compliance_refs.items():
        verify_refs[req_id].update(locs)

    # Collect all known requirements
    all_reqs = sorted(set(REQ_NAMES.keys()) | set(impl_refs.keys()) |
                      set(verify_refs.keys()))

    # Print matrix
    print("# FBVBS Requirement Traceability Matrix")
    print()
    print(f"Generated: {date.today().isoformat()}")
    src_file_count = len({f for locs in src_refs.values() for f, _ in locs})
    inc_file_count = len({f for locs in inc_refs.values() for f, _ in locs})
    print(f"Source files scanned: {src_file_count} src + "
          f"{inc_file_count} include")
    print()

    # Summary counts
    implemented = sum(1 for r in all_reqs if r in impl_refs)
    verified = sum(1 for r in all_reqs if r in verify_refs)
    total = len(all_reqs)
    print(f"**Summary:** {total} requirements tracked, "
          f"{implemented} with source references, "
          f"{verified} with test/compliance references")
    print()

    print("| REQ | Description | Implementation | Verification |")
    print("|-----|-------------|----------------|--------------|")

    for req_id in all_reqs:
        name = REQ_NAMES.get(req_id, "???")
        # Format implementation refs
        impl_locs = sorted(impl_refs.get(req_id, set()))
        if impl_locs:
            # Group by file
            by_file = defaultdict(list)
            for fname, lineno in impl_locs:
                by_file[fname].append(lineno)
            impl_parts = []
            for fname in sorted(by_file.keys()):
                lines = sorted(by_file[fname])
                if len(lines) <= 3:
                    impl_parts.append(f"{fname}:{','.join(str(l) for l in lines)}")
                else:
                    impl_parts.append(f"{fname}:({len(lines)} refs)")

            impl_str = "; ".join(impl_parts[:3])
            if len(impl_parts) > 3:
                impl_str += f" +{len(impl_parts)-3}"
        else:
            impl_str = "—"

        # Format verification refs
        ver_locs = sorted(verify_refs.get(req_id, set()))
        if ver_locs:
            by_file = defaultdict(list)
            for fname, lineno in ver_locs:
                by_file[fname].append(lineno)
            ver_parts = []
            for fname in sorted(by_file.keys()):
                lines = sorted(by_file[fname])
                ver_parts.append(f"{fname}:{','.join(str(l) for l in lines[:3])}")
            ver_str = "; ".join(ver_parts[:3])
        else:
            ver_str = "—"

        print(f"| REQ-{req_id} | {name} | {impl_str} | {ver_str} |")

    # Orphan check
    print()
    print("## Orphan Analysis")
    print()
    no_impl = [r for r in all_reqs if r not in impl_refs]
    no_verify = [r for r in all_reqs if r not in verify_refs and r in impl_refs]
    print(f"- Requirements with NO source reference: {len(no_impl)}")
    for r in no_impl:
        print(f"  - REQ-{r}: {REQ_NAMES.get(r, '???')}")
    print(f"- Implemented but NO test/compliance reference: {len(no_verify)}")
    for r in no_verify:
        print(f"  - REQ-{r}: {REQ_NAMES.get(r, '???')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
