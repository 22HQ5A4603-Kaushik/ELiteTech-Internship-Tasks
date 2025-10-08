# file_integrity_checker.py
import os
import hashlib
import json
import argparse

def calculate_hash(file_path):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def create_baseline(directory, output_file):
    """Create a baseline of file hashes in a directory."""
    baseline = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            baseline[file_path] = calculate_hash(file_path)

    with open(output_file, "w") as f:
        json.dump(baseline, f, indent=4)

    print(f"[+] Baseline created and saved to {output_file}")

def check_baseline(directory, baseline_file):
    """Check files against the baseline for changes."""
    if not os.path.exists(baseline_file):
        print(f"[!] Baseline file {baseline_file} not found.")
        return

    with open(baseline_file, "r") as f:
        baseline = json.load(f)

    current = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            current[file_path] = calculate_hash(file_path)

    modified = [f for f in current if f in baseline and current[f] != baseline[f]]
    new_files = [f for f in current if f not in baseline]
    deleted = [f for f in baseline if f not in current]

    if not modified and not new_files and not deleted:
        print("[+] No changes detected.")
    else:
        print("[-] Changes detected:")
        if modified:
            print("Modified files:")
            for f in modified:
                print(f"  {f}")
        if new_files:
            print("New files:")
            for f in new_files:
                print(f"  {f}")
        if deleted:
            print("Deleted files:")
            for f in deleted:
                print(f"  {f}")

def main():
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("mode", nargs="?", choices=["create", "check"], default="create",
                        help="Mode: create baseline or check baseline (default: create)")
    parser.add_argument("path", nargs="?", default=".",
                        help="Directory to scan (default: current directory)")
    parser.add_argument("--out", default="baseline.json",
                        help="Baseline output file (default: baseline.json)")

    args = parser.parse_args()

    if args.mode == "create":
        create_baseline(args.path, args.out)
    else:
        check_baseline(args.path, args.out)

if __name__ == "__main__":
    main()
