import json
import sys
from collections import defaultdict
import re
import cert_equivalence
import subprocess

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

def parse_diff_to_json(diff_text):
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

    so_counter = 0
    for line in lines:
            
        parts = line.split()
        #path = ""
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
                if so_match:
                    #print(path)
                    so_counter += 1
                    so_path_1, so_path_2 = reconstruct_paths(path)
                    
                    #print("so_counter: ", so_counter)
                    cmd = [
                        "radiff2",
                        "-AC",
                        "-e", "bin.relocs.apply=true",
                        so_path_1,
                        so_path_2
                    ]
                    #print("so_counter: ", so_counter)
                    #result = subprocess.run(cmd, capture_output=True, text=True)
                    #extra_analysis = result.stdout
                    extra_analysis = "so_analysis"

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

    root["__renamed__"] = renamed_files
    return root

def dump_json(filename, topmost_key = None):
    diff_text = open(filename, "r").read()
    result = parse_diff_to_json(diff_text)

    if topmost_key is not None:
        result = wrap_json_with_topmost_key(result, topmost_key)

    from copy import deepcopy
    output_json = deepcopy(result)

    aggregate_totals(output_json)
    return json.dumps(output_json, indent=4)


if __name__ == "__main__":
    res = dump_json("shorter.diff")
    print(res)
