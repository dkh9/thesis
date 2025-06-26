import json
import sys
from collections import defaultdict
import re
import cert_equivalence
import subprocess
import tempfile
import shutil
import summarize_radiff as radigest
import argparse
from os.path import basename
import os
from pathlib import Path

def extract_tail_path(path, levels=3):
    p = Path(path)
    return str(Path(*p.parts[-levels:]))

def is_executable_elf(path):
    try:
        output = subprocess.check_output(["file", path], text=True)
        return "ELF" in output and "executable" in output
    except subprocess.CalledProcessError:
        return False

def wrap_json_with_topmost_key(original_json, topmost_key):
    if not isinstance(original_json, dict):
        raise ValueError("original_json must be a dictionary")
    
    if not isinstance(topmost_key, str):
        raise ValueError("topmost_key must be a string")
    
    return {topmost_key: original_json}

def aggregate_totals(data):
    if isinstance(data, dict):
        added_total, deleted_total = 0, 0
        for key, value in data.items():
            if key == "__renamed__":
                continue
            if isinstance(value, dict) and "added" in value and "deleted" in value:
                #if value.get("status") == "renamed":
                #    continue 
                added_total += value["added"] if value["added"] != "NONTEXT" else 0
                deleted_total += value["deleted"] if value["deleted"] != "NONTEXT" else 0
            else:
                child_added, child_deleted = aggregate_totals(value)
                added_total += child_added
                deleted_total += child_deleted

        data["added"] = added_total
        data["deleted"] = deleted_total

        return added_total, deleted_total
    return 0, 0

def reconstruct_paths(diff_path):
    match = re.search(r'\{([^{}]+?)\s*=>\s*([^{}]+?)\}', diff_path)
    if not match:
        # No brace-style replacement, return original twice
        print("No match!")
        return diff_path, diff_path

    old_part, new_part = match.groups()
    before = diff_path[:match.start()]
    after = diff_path[match.end():]

    old_path = f"{before}{old_part}{after}"
    new_path = f"{before}{new_part}{after}"
    return old_path, new_path

def parse_diff_to_json(diff_text, rc_bin_paths=None, rc_libs=None):
    if rc_bin_paths is None:
        rc_bin_paths = []
    if rc_libs is None:
        rc_libs = {}

    def add_to_hierarchy(path_parts, stats, current_dict, status_string, extra_analysis_info):
        if len(path_parts) == 1:
            current_dict[path_parts[0]] = {
                "added": int(stats[0]) if stats[0] != "-" else "NONTEXT",
                "deleted": int(stats[1]) if stats[1] != "-" else "NONTEXT",
                "status": status_string,
                "analysis": extra_analysis_info
            }
        else:
            dir_name = path_parts[0]
            if dir_name not in current_dict:
                current_dict[dir_name] = {}
            add_to_hierarchy(path_parts[1:], stats, current_dict[dir_name], status_string, extra_analysis_info)

    root = {}
    lines = diff_text.strip().split("\n")
    renamed_files = {}

    brace_rename_pattern = re.compile(r'\{([^{}]+) => ([^{}]+)\}(/.+)')
    so_pattern = re.compile(r'\{([^{}]+)\s*=>\s*([^{}]+)\}[^{}]*\/([\w.-]+\.so)')
    apk_pattern = re.compile(r'([\w./-]+\.apk)')

    so_counter = 0
    formatted_digests = {}
    for line in lines:
        parts = line.split()
        added, deleted = parts[:2]
        path = parts[2]
        status = ""
        extra_analysis = ""

        if "=>" in line:
            if parts[2].startswith("{") and parts[3] == "=>":

                match = brace_rename_pattern.search(line)
                if match:
                    if "/" in match.group(1) or "/" in match.group(2):
                        old_prefix, new_prefix, suffix = match.groups()
                        old_path = old_prefix + suffix
                        new_path = new_prefix + suffix

                        status = "renamed"
                        renamed_files[new_path] = {
                            "old_path": old_path,
                            "added": int(added) if added.isdigit() else 0,
                            "deleted": int(deleted) if deleted.isdigit() else 0,
                            "analysis": ""
                        }
                        continue

                path = parts[2] + parts[3] + parts[4]
                status = "modified"
                so_match = so_pattern.search(path)
                apk_match = apk_pattern.search(path)
                so_path_1, so_path_2 = reconstruct_paths(path)


                if so_match or radigest.is_executable_elf(so_path_2):
                    mentioned_in_rc = "false"
                    is_shared_lib = so_match is not None
                    lib_or_bin_name = basename(so_path_2)  # we use *_2 because that's the newer one

                    checksec_props = radigest.compare_checksec_properties(so_path_1, so_path_2)
                    similarity, distance = radigest.get_similarity_and_distance(so_path_1, so_path_2)
                    summary = radigest.parse_function_diffs(so_path_1, so_path_2)
                    total = summary["total_functions"]
                    changed = summary["changed"]
                    
                    digest = {
                        "Similarity Score": round(similarity, 3),
                        "Radiff2 Distance": distance,
                        "Total Functions Analyzed": total,
                        "Identical Functions": summary['identical'],
                        "New Functions": summary['new'],
                        "Changed Functions (sim < 1.0, excluding NEW)": changed,
                        "Changed Matched Functions": summary['changed matched'],
                        "Changed Unmatched Functions": summary['changed unmatched'],
                        "Mentioned in .rc": False,  # default, updated below
                        "Hardening comparison" : checksec_props
                    }
                    
                    # === Check for .rc mention ===
                    if is_shared_lib:
                        if lib_or_bin_name in rc_libs:
                            digest["Mentioned in .rc"] = True
                            digest["Used By"] = [os.path.basename(p) for p in rc_libs[lib_or_bin_name]]
                            mentioned_in_rc = "true"
                    else:
                        matched_rc_bin = any(p.endswith(so_path_2) for p in rc_bin_paths)
                        if matched_rc_bin:
                            digest["Mentioned in .rc"] = True
                            mentioned_in_rc = "true"
                    
                    formatted_summary = (
                        #f"\n=== Summary for {lib_name} ===\n"
                        f"Similarity Score: {similarity:.3f}\n"
                        f"Radiff2 Distance: {distance}\n"
                        f"Total functions analyzed: {total}\n"
                        f"- Identical functions: {summary['identical']} ({summary['identical'] / total:.1%})\n"
                        f"- New functions: {summary['new']} ({summary['new'] / total:.1%})\n"
                        f"- Changed functions (sim < 1.0, excluding NEW): {changed} ({changed / total:.1%})\n"
                        f"- Changed matched functions: {summary['changed matched']} ({summary['changed matched'] / total:.1%})\n"
                        f"- Changed unmatched functions: {summary['changed unmatched']} ({summary['changed unmatched'] / total:.1%})"
                    )

                    # === Determine name to use as JSON key ===
                    formatted_digests[extract_tail_path(so_path_2, 4)] = digest

                    extra_analysis += formatted_summary
                    extra_analysis += "\nMentioned in rc:" + mentioned_in_rc
                    extra_analysis += checksec_props

                
                elif apk_match:
                    apk_path_1, apk_path_2 = reconstruct_paths(path)
                    #extra_analysis = f"apk_file:\n  old_path: {apk_path_1}\n  new_path: {apk_path_2}"
                        # Create temporary directories
                    tmp_dir1 = tempfile.mkdtemp(prefix="apk1_")
                    tmp_dir2 = tempfile.mkdtemp(prefix="apk2_")
                
                    try:
                        subprocess.run(["unzip", "-q", apk_path_1, "-d", tmp_dir1], check=True)
                        subprocess.run(["unzip", "-q", apk_path_2, "-d", tmp_dir2], check=True)

                        # Run git diff --no-index --numstat
                        diff_result = subprocess.run(
                            ["git", "diff", "--no-index", "--numstat", tmp_dir1, tmp_dir2],
                            capture_output=True, text=True
                        )
                        diff_output = diff_result.stdout.strip()

                        # Check for AndroidManifest.xml in the diff
                        manifest_changed = any("AndroidManifest.xml" in line for line in diff_output.splitlines())
                        manifest_status = "AndroidManifest.xml changed: yes" if manifest_changed else "AndroidManifest.xml changed: no"

                        # Prepare the final extra_analysis
                        extra_analysis = diff_output + "\n\n" + manifest_status

                    except subprocess.CalledProcessError as e:
                        extra_analysis = f"Error processing APK diff: {e}"
                    finally:
                        # Clean up temporary directories
                        shutil.rmtree(tmp_dir1)
                        shutil.rmtree(tmp_dir2)


                elif "security/cacerts" in path:
                    cert1, cert2 = reconstruct_paths(path)
                    are_different = cert_equivalence.main(cert1, cert2)
                    if are_different:
                        result = subprocess.run(
                            ["git", "diff", "--no-index", cert1, cert2],
                            capture_output=True,
                            text=True,
                        )
                        extra_analysis = result.stdout

            elif parts[2] == "/dev/null" and parts[3] == "=>":
                path = parts[4]
                status = "added"
                if "security/cacerts" in path:
                    f = open(path)
                    extra_analysis = f.read()
                    f.close()

            elif parts[4] == "/dev/null" and parts[3] == "=>":
                path = parts[2]
                status = "deleted"
                if "security/cacerts" in path:
                    f = open(path)
                    extra_analysis = f.read()
                    f.close()
            
            #true rename
            elif parts[3] == "=>":
                old_path = parts[2]
                path = parts[4]

                status = "renamed"

                renamed_files[path] = {
                    "old_path": old_path,
                    "added": added,
                    "deleted": deleted,
                    "status": "renamed",
                    "analysis": ""
                }
                continue

            else:
                # Fallback, shouldn't really occur
                path = parts[4]
                status = "modified"

        else:
            path = parts[2]
            status = "modified"

        path_parts = []
        path_parts = path.split("/")
        add_to_hierarchy(path_parts, (added, deleted), root, status, extra_analysis)
    
    with open("formatted_digests.json", "w") as f:
        json.dump(formatted_digests, f, indent=2)

    root["__renamed__"] = renamed_files
    return root

def dump_json(filename, bins_in_rc, elf_libs_file, topmost_key = None):
    diff_text = open(filename, "r").read()

    full_rc_bin_paths = []
    rc_libs = {}
    with open(bins_in_rc, "r") as f:
        for line in f:
            binary_path = line.strip()
            if not binary_path:
                continue
            full_rc_bin_paths.append(binary_path)
    print(full_rc_bin_paths)
    print("-------------------------------------------------")

    import json

    with open(elf_libs_file) as f:
        rc_libs = json.load(f)
    print(rc_libs)
    print("-------------------------------------------------")

    
    result = parse_diff_to_json(diff_text, full_rc_bin_paths, rc_libs)
    #result = parse_diff_to_json(diff_text)


    if topmost_key is not None:
        result = wrap_json_with_topmost_key(result, topmost_key)

    from copy import deepcopy
    output_json = deepcopy(result)

    aggregate_totals(output_json)
    return json.dumps(output_json, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dump json digest")
    parser.add_argument("diff_file", help="File containing git diff digest")
    parser.add_argument("bins_in_rc", help="File containing a list of bins in .rc files")
    parser.add_argument("elf_libs", help="JSON file containing shared libs to bins from init.rc mapping")
    
    args = parser.parse_args()
    res = dump_json(args.diff_file, args.bins_in_rc, args.elf_libs)
    #print(res)
    with open("a15-full-401-850.json", "w") as f:
        f.write(res)
