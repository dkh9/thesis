import subprocess
import re
import sys
from pathlib import Path
import json

def is_executable_elf(path):
    try:
        output = subprocess.check_output(["file", path], text=True)
        return "ELF" in output and "executable" in output
    except subprocess.CalledProcessError:
        return False

def get_similarity_and_distance(file1, file2):
    cmd = [
        "radiff2", "-s",
        "-e", "bin.relocs.apply=true",
        file1, file2
    ]
    try:
        output = subprocess.check_output(cmd, text=True)
        match = re.search(r"similarity:\s+([0-9.]+)\s+distance:\s+(\d+)", output)
        if match:
            similarity = float(match.group(1))
            distance = int(match.group(2))
            return similarity, distance
    except subprocess.CalledProcessError as e:
        print("Error running radiff2 -s:", e)
    return None, None

def parse_function_diffs(file1, file2):
    cmd = [
        "radiff2", "-AC",
        "-e", "bin.relocs.apply=true",
        file1, file2
    ]
    try:
        output = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        print("Error running radiff2 -AC:", e)
        return None

    func_lines = [line for line in output.splitlines() if re.search(r'\b(MATCH|UNMATCH|NEW)\b', line)]

    summary = {
        "total_functions": 0,
        "identical": 0,
        "changed": 0,  # Any non-NEW function with sim < 1.0
        "changed matched": 0,
        "changed unmatched": 0,
        "new": 0,
    }

    for line in func_lines:
        summary["total_functions"] += 1

        if "NEW" in line:
            summary["new"] += 1
            continue  # NEW functions are never "changed" by definition

        # Extract similarity score (if present)
        sim_match = re.search(r'\((0\.\d+)\)', line)
        similarity = float(sim_match.group(1)) if sim_match else 1.0

        if similarity < 1.0:
            summary["changed"] += 1
            if "UNMATCH" in line: #make sure to not change order of this check lmao
                summary["changed unmatched"] += 1
            elif "MATCH" in line:
                summary["changed matched"] += 1

        else:
            summary["identical"] +=1

    return summary

def compare_checksec_properties(file1, file2):
    def run_checksec(path):
        cmd = ["checksec", "--format=json", f"--file={path}"]
        output = subprocess.check_output(cmd, text=True)
        return json.loads(output)[path]

    try:
        props1 = run_checksec(file1)
        props2 = run_checksec(file2)
    except subprocess.CalledProcessError as e:
        return f"Error running checksec on {file1} or {file2}:\n{e}"

    lines = ["\n=== Checksec Hardening Comparison ==="]
    if props1 == props2:
        lines.append("Security hardening properties are identical:")
        for k, v in props1.items():
            lines.append(f"- {k}: {v}")
    else:
        lines.append("Security hardening differences detected:")
        all_keys = sorted(set(props1.keys()) | set(props2.keys()))
        for key in all_keys:
            v1 = props1.get(key, "<missing>")
            v2 = props2.get(key, "<missing>")
            if v1 != v2:
                lines.append(f"- {key}:")
                lines.append(f"  old: {v1}")
                lines.append(f"  new: {v2}")
    return "\n".join(lines)

def print_summary(lib_name, summary, similarity, distance):
    total = summary["total_functions"]
    changed = summary["changed"]

    print(f"\n=== Summary for {lib_name} ===")
    print(f"Similarity Score: {similarity:.3f}")
    print(f"Radiff2 Distance: {distance}")
    print(f"Total functions analyzed: {total}")
    print(f"- Identical functions: {summary['identical']} ({summary['identical'] / total:.1%})")
    print(f"- New functions: {summary['new']} ({summary['new'] / total:.1%})")
    print(f"- Changed functions (sim < 1.0, excluding NEW): {changed} ({changed / total:.1%})")
    print(f"- Changed matched functions: {summary['changed matched']} ({summary['changed matched'] / total:.1%})")
    print(f"- Changed unmatched functions: {summary['changed unmatched']} ({summary['changed unmatched'] / total:.1%})")
    


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python summarize_radiff_full.py <old.so> <new.so>")
        sys.exit(1)

    old_so, new_so = sys.argv[1], sys.argv[2]
    lib_name = Path(new_so).name

    similarity, distance = get_similarity_and_distance(old_so, new_so)
    if similarity is None:
        sys.exit("Could not extract similarity/distance.")

    summary = parse_function_diffs(old_so, new_so)
    if summary is None:
        sys.exit("Could not parse function diffs.")

    print_summary(lib_name, summary, similarity, distance)
    print(compare_checksec_properties(old_so, new_so))
    print("Is executable elf?")
    print(is_executable_elf(old_so))
