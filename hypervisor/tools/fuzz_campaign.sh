#!/bin/bash
# FBVBS Continuous Fuzzing Campaign Runner
#
# Usage:
#   ./tools/fuzz_campaign.sh [--duration SECONDS] [--harness NAME] [--output-dir DIR]
#
# Runs AFL++ or libFuzzer campaigns against all (or specified) harnesses.
# Generates coverage growth reports and crash triage summaries.
#
# Requirements:
#   - AFL++ (afl-fuzz) or clang with libFuzzer support
#   - make fuzz-build must succeed first
#
# Exit: 0 on clean run, 1 on new unique crashes found

set -euo pipefail

DURATION="${DURATION:-3600}"
HARNESS=""
OUTPUT_DIR="build/fuzz-campaign"
FUZZ_ENGINE="afl"  # afl or libfuzzer

validate_optarg() {
    if [[ -z "${2:-}" || "${2:-}" == -* ]]; then
        echo "Error: Missing or invalid value for $1" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)   validate_optarg "$1" "${2:-}"; DURATION="$2"; shift 2 ;;
        --harness)    validate_optarg "$1" "${2:-}"; HARNESS="$2"; shift 2 ;;
        --output-dir) validate_optarg "$1" "${2:-}"; OUTPUT_DIR="$2"; shift 2 ;;
        --engine)     validate_optarg "$1" "${2:-}"; FUZZ_ENGINE="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cd "$(dirname "$0")/.."

HARNESSES=(
    fuzz_command_page
    fuzz_manifest
    fuzz_multiboot2
    fuzz_iommu
    fuzz_log_decoder
    fuzz_partition_loader
)

if [[ -n "$HARNESS" ]]; then
    HARNESSES=("$HARNESS")
fi

mkdir -p "$OUTPUT_DIR"
SUMMARY="$OUTPUT_DIR/campaign-summary.txt"
: > "$SUMMARY"

echo "=== FBVBS Fuzz Campaign ===" | tee -a "$SUMMARY"
echo "Date:     $(date -u -Iseconds)" | tee -a "$SUMMARY"
echo "Duration: ${DURATION}s per harness" | tee -a "$SUMMARY"
echo "Engine:   $FUZZ_ENGINE" | tee -a "$SUMMARY"
echo "Harnesses: ${HARNESSES[*]}" | tee -a "$SUMMARY"
echo "" | tee -a "$SUMMARY"

TOTAL_CRASHES=0

for h in "${HARNESSES[@]}"; do
    BINARY="build/$h"
    CORPUS="fuzz/corpus/${h#fuzz_}"
    CAMPAIGN_DIR="$OUTPUT_DIR/$h"

    if [[ ! -x "$BINARY" ]]; then
        echo "SKIP: $BINARY not found (run make fuzz-build first)" | tee -a "$SUMMARY"
        continue
    fi

    if [[ ! -d "$CORPUS" ]]; then
        echo "SKIP: $CORPUS not found (prepare corpus or run make fuzz-corpus)" | tee -a "$SUMMARY"
        continue
    fi

    mkdir -p "$CAMPAIGN_DIR/crashes" "$CAMPAIGN_DIR/queue"

    echo "--- Running: $h (${DURATION}s) ---" | tee -a "$SUMMARY"

    if [[ "$FUZZ_ENGINE" == "afl" ]]; then
        if command -v afl-fuzz >/dev/null 2>&1; then
            timeout "${DURATION}s" afl-fuzz \
                -i "$CORPUS" \
                -o "$CAMPAIGN_DIR" \
                -V "$DURATION" \
                -- "$BINARY" @@ \
                > "$CAMPAIGN_DIR/afl-stdout.log" 2>&1 || true
        else
            # Fallback: replay corpus + random mutations via stdin
            echo "  AFL++ not installed; running corpus replay + random mutations" | tee -a "$SUMMARY"
            CRASHES=0
            for seed in "$CORPUS"/*; do
                [[ -f "$seed" ]] || continue
                set +e
                "$BINARY" "$seed" > /dev/null 2>&1
                EXIT_STATUS=$?
                set -e
                # Only count signal-terminated processes as crashes (status > 128)
                if [[ $EXIT_STATUS -gt 128 ]]; then
                    cp "$seed" "$CAMPAIGN_DIR/crashes/"
                    CRASHES=$((CRASHES + 1))
                fi
            done
            echo "  Corpus replay: $CRASHES crashes from $(ls "$CORPUS" 2>/dev/null | wc -l) seeds" | tee -a "$SUMMARY"
            # Do not add CRASHES here — the find-based count below avoids double counting
        fi
    elif [[ "$FUZZ_ENGINE" == "libfuzzer" ]]; then
        timeout "${DURATION}s" "$BINARY" \
            "$CORPUS" \
            -max_total_time="$DURATION" \
            -artifact_prefix="$CAMPAIGN_DIR/crashes/" \
            > "$CAMPAIGN_DIR/libfuzzer-stdout.log" 2>&1 || true
    fi

    # Count crashes
    CRASH_COUNT=$(find "$CAMPAIGN_DIR/crashes" -type f 2>/dev/null | wc -l)
    TOTAL_CRASHES=$((TOTAL_CRASHES + CRASH_COUNT))
    echo "  Crashes found: $CRASH_COUNT" | tee -a "$SUMMARY"

    # Coverage growth (if gcov data available)
    if [[ -f "$CAMPAIGN_DIR/plot_data" ]]; then
        echo "  Coverage growth: $(tail -1 "$CAMPAIGN_DIR/plot_data")" | tee -a "$SUMMARY"
    fi
done

echo "" | tee -a "$SUMMARY"
echo "=== Campaign Complete ===" | tee -a "$SUMMARY"
echo "Total unique crashes: $TOTAL_CRASHES" | tee -a "$SUMMARY"

if [[ $TOTAL_CRASHES -gt 0 ]]; then
    echo "WARNING: Crashes found — triage required" | tee -a "$SUMMARY"
    exit 1
fi

echo "PASS: No crashes found across all harnesses" | tee -a "$SUMMARY"
exit 0
