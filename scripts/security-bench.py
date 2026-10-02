#!/usr/bin/env python3
import argparse
import csv
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIREMENTS = os.path.join(ROOT, "security", "requirements.tsv")
TEST_LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\b")


def run_tests(log_path):
    command = ["cargo", "test", "--workspace", "--release", "--no-fail-fast"]
    print("$ " + " ".join(command), file=sys.stderr)
    with open(log_path, "w") as log:
        process = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    return process.returncode


def parse_results(log_path):
    results = defaultdict(list)
    with open(log_path, errors="replace") as log:
        for line in log:
            match = TEST_LINE.match(line.strip())
            if match:
                results[match.group(1).split("::")[-1]].append(match.group(2))
    return results


def load_requirements(path):
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def outcome(tests, results):
    if not tests:
        return "untested", 0, 0
    passed = 0
    for test in tests:
        states = results.get(test)
        if not states:
            return "missing", passed, len(tests)
        if "FAILED" in states:
            return "fail", passed, len(tests)
        if all(state == "ok" for state in states):
            passed += 1
    return ("pass" if passed == len(tests) else "ignored"), passed, len(tests)


def main():
    parser = argparse.ArgumentParser(description="Run the MTProto security bench and report every requirement.")
    parser.add_argument("--log", help="parse an existing `cargo test` log instead of running the tests")
    parser.add_argument("--area", action="append", help="only report these areas (crypto, messages, transport, ...)")
    parser.add_argument("--status", action="append", help="only report requirements with these audit statuses")
    parser.add_argument("--markdown", action="store_true", help="print a Markdown table")
    parser.add_argument("--quiet", action="store_true", help="print only failing rows and the summary")
    args = parser.parse_args()

    log_path = args.log
    cargo_status = None
    if not log_path:
        os.makedirs(os.path.join(ROOT, "target"), exist_ok=True)
        log_path = os.path.join(ROOT, "target", "security-bench.log")
        cargo_status = run_tests(log_path)
    results = parse_results(log_path)
    with open(log_path, errors="replace") as log:
        workspace_failed = any(line.startswith("test result: FAILED") or line.startswith("error: ") for line in log)
    if not results:
        print(f"no test results found in {log_path}", file=sys.stderr)
        return 2

    rows = load_requirements(REQUIREMENTS)
    if args.area:
        rows = [row for row in rows if row["area"] in args.area]
    if args.status:
        rows = [row for row in rows if row["status"] in args.status]

    outcomes = Counter()
    statuses = Counter()
    failing = []
    lines = []
    for row in rows:
        tests = [test for test in row["tests"].split(",") if test]
        result, passed, total = outcome(tests, results)
        outcomes[result] += 1
        statuses[row["status"]] += 1
        if result in ("fail", "missing"):
            failing.append((row["id"], result, [test for test in tests if "ok" not in results.get(test, [])]))
        if args.quiet and result not in ("fail", "missing"):
            continue
        cells = [row["id"], row["area"], row["status"], row["owner"], f"{result} {passed}/{total}", row["requirement"]]
        lines.append(cells)

    if args.markdown:
        print("| id | area | status | owner | tests | requirement |")
        print("|---|---|---|---|---|---|")
        for cells in lines:
            print("| " + " | ".join(cell.replace("|", "/") for cell in cells) + " |")
    else:
        for cells in lines:
            print(f"{cells[0]:<6} {cells[1]:<10} {cells[2]:<9} {cells[3]:<6} {cells[4]:<12} {cells[5][:90]}")

    executed = sum(len(states) for states in results.values())
    print()
    print(f"requirements: {len(rows)}  " + "  ".join(f"{key}={value}" for key, value in sorted(statuses.items())))
    print(f"bench: " + "  ".join(f"{key}={outcomes[key]}" for key in ("pass", "fail", "missing", "ignored", "untested")))
    print(f"tests executed: {executed}")
    for row_id, result, tests in failing:
        print(f"  {row_id} {result}: {', '.join(tests)}")
    if workspace_failed or (cargo_status not in (None, 0)):
        print(f"cargo test did not pass (see {log_path}); a test outside the table, a doctest or a build failed")
        return 1
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
