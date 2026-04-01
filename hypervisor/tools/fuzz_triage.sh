#!/bin/bash
# FBVBS Crash Triage Script
#
# Usage: ./tools/fuzz_triage.sh [--campaign-dir DIR]
#
# Deduplicates crashes by stack hash, produces a triage report.

set -euo pipefail

CAMPAIGN_DIR="build/fuzz-campaign"
REPLAY_TIMEOUT=10

while [[ $# -gt 0 ]]; do
    case $1 in
        --campaign-dir)
            if [[ -z "${2:-}" || "${2:-}" == -* ]]; then
                echo "Error: Missing value for --campaign-dir" >&2
                exit 1
            fi
            CAMPAIGN_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cd "$(dirname "$0")/.."

# Verify CAMPAIGN_DIR exists and is a directory
if [[ ! -d "$CAMPAIGN_DIR" ]]; then
    echo "Error: Campaign directory does not exist or is not a directory: $CAMPAIGN_DIR" >&2
    exit 1
fi

REPORT="$CAMPAIGN_DIR/triage-report.txt"
: > "$REPORT"

echo "=== FBVBS Crash Triage Report ===" | tee -a "$REPORT"
echo "Date: $(date -u -Iseconds)" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

TOTAL=0
UNIQUE=0

for harness_dir in "$CAMPAIGN_DIR"/fuzz_*; do
    [[ -d "$harness_dir/crashes" ]] || continue
    HARNESS=$(basename "$harness_dir")
    mapfile -d '' CRASH_FILES < <(find "$harness_dir/crashes" -type f -print0 2>/dev/null)
    COUNT=${#CRASH_FILES[@]}

    if [[ $COUNT -eq 0 ]]; then
        echo "--- $HARNESS: 0 crashes ---" | tee -a "$REPORT"
        continue
    fi

    TOTAL=$((TOTAL + COUNT))
    echo "--- $HARNESS: $COUNT crash files ---" | tee -a "$REPORT"

    # Deduplicate by file hash
    declare -A SEEN_HASHES
    HARNESS_UNIQUE=0
    for crash in "${CRASH_FILES[@]}"; do
        HASH=$(sha256sum "$crash" | cut -d' ' -f1)
        if [[ -z "${SEEN_HASHES[$HASH]:-}" ]]; then
            SEEN_HASHES[$HASH]=1
            HARNESS_UNIQUE=$((HARNESS_UNIQUE + 1))
            SIZE=$(stat -c%s "$crash" 2>/dev/null || echo "?")
            echo "  [UNIQUE] $crash (${SIZE}B, sha256:${HASH:0:16}...)" | tee -a "$REPORT"

            # Try to replay and capture signal
            BINARY="build/$HARNESS"
            if [[ -x "$BINARY" ]]; then
                set +e
                timeout "$REPLAY_TIMEOUT" "$BINARY" < "$crash" > /dev/null 2>&1
                EXIT_CODE=$?
                set -e
                if [[ $EXIT_CODE -eq 124 || $EXIT_CODE -eq 137 ]]; then
                    echo "    Timed out after ${REPLAY_TIMEOUT}s" | tee -a "$REPORT"
                elif [[ $EXIT_CODE -gt 128 ]]; then
                    SIG=$((EXIT_CODE - 128))
                    echo "    Signal: $SIG ($(kill -l "$SIG" 2>/dev/null || echo 'unknown'))" | tee -a "$REPORT"
                else
                    echo "    Exit code: $EXIT_CODE" | tee -a "$REPORT"
                fi
            fi
        fi
    done
    unset SEEN_HASHES
    UNIQUE=$((UNIQUE + HARNESS_UNIQUE))
    echo "  Unique: $HARNESS_UNIQUE / $COUNT" | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
done

echo "=== Summary ===" | tee -a "$REPORT"
echo "Total crash files: $TOTAL" | tee -a "$REPORT"
echo "Unique crashes:    $UNIQUE" | tee -a "$REPORT"

if [[ $UNIQUE -gt 0 ]]; then
    echo "STATUS: TRIAGE REQUIRED" | tee -a "$REPORT"
    exit 1
fi

echo "STATUS: CLEAN" | tee -a "$REPORT"
exit 0
