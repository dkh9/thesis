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

TIER_3_IGNORED_PREFIXES = (
    "META-INF/", "SEC-INF/", "META-INF/CERT.RSA", "META-INF/CERT.SF", "META-INF/MANIFEST.MF"
)
TIER_1_CRITICAL = ("classes", "AndroidManifest.xml")
TIER_2_MEANINGFUL = ("lib/", "assets/", "res/", "resources.arsc", "kotlin/", "smali/")

APK_PREFIX_PATTERN = re.compile(r"apk[12]_[^/]+/")
#APK_PREFIX_PATTERN = re.compile(r"^(tmp/)?apk[12]_[^/]+/")

def normalize_rel_path(rel_path: str) -> str:
    return APK_PREFIX_PATTERN.sub("", rel_path)

def categorize_path(path: str) -> str:
    # Normalize path: remove leading apk1_xxx/ or apk2_xxx/ prefix
    path = APK_PREFIX_PATTERN.sub("", path)
    parts = path.split("/", 1)
    if len(parts) == 2:
        path = parts[1]

    if path.startswith(TIER_3_IGNORED_PREFIXES):
        return "tier_3"
    if any(key in path for key in TIER_1_CRITICAL):
        return "tier_1"
    if any(key in path for key in TIER_2_MEANINGFUL):
        return "tier_2"
    return "unclassified"

def looks_encrypted(path):
    from math import log2
    from collections import Counter

    def entropy(data):
        total = len(data)
        counts = Counter(data)
        return -sum(c / total * log2(c / total) for c in counts.values())

    with open(path, "rb") as f:
        chunk = f.read(4096)
        return entropy(chunk) > 7.5  # threshold for randomness


def format_checksec_summary(checksec_props):
    if "error" in checksec_props:
        return f"Checksec Error: {checksec_props['error']}"

    lines = ["\n=== Checksec Hardening Comparison ==="]
    if checksec_props.get("identical", False):
        lines.append("Security hardening properties are identical.")
    else:
        lines.append("Differences in hardening detected:")
        for diff in checksec_props.get("differences", []):
            line = f"- {diff['option']}: {diff['old']} → {diff['new']} ({diff['change']})"
            if "extra_info" in diff:
                line += f" [{diff['extra_info']}]"
            lines.append(line)
    return "\n".join(lines)

def is_tee_trusted_app(path):
    try:
        with open(path, "rb") as f:
            header = f.read(16)
            if header.startswith(b"SEC3") and b"\x7fELF" in header:
                return True
            if header.startswith(b"SEC2") and b"\x7fELF" in header:
                return True
    except Exception:
        return False

def strip_sec3_header(input_path, output_path):
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        data = fin.read()
        elf_offset = data.find(b"\x7fELF")
        if elf_offset == -1:
            raise ValueError(f"ELF header not found in {input_path}")
        fout.write(data[elf_offset:])

def analyze_tee_trusted_app(path, ta1_path, ta2_path, rc_bin_paths):
    tmp1 = tempfile.NamedTemporaryFile(delete=False, suffix=".ta.elf")
    tmp2 = tempfile.NamedTemporaryFile(delete=False, suffix=".ta.elf")

    strip_sec3_header(ta1_path, tmp1.name)
    strip_sec3_header(ta2_path, tmp2.name)

    checksec_props = radigest.compare_checksec_properties(tmp1.name, tmp2.name)
    similarity, distance = radigest.get_similarity_and_distance(tmp1.name, tmp2.name)
    summary = radigest.parse_function_diffs(tmp1.name, tmp2.name)
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
        #"Mentioned in .rc": any(p.endswith(ta2_path) for p in rc_bin_paths),
        "TEE": True,
        "Hardening comparison": checksec_props,
        "Obfuscated": False
    }
    
    ta2_path_str = os.path.abspath(str(ta2_path))

    if ta2_path_str in rc_bin_json:
        digest["Mentioned in .rc"] = True
        digest["rc_metadata"] = rc_bin_json[ta2_path_str]

    formatted_summary = (
        f"Similarity Score: {digest['Similarity Score']:.3f}\n"
        f"Radiff2 Distance: {digest['Radiff2 Distance']}\n"
        f"Total functions analyzed: {digest['Total Functions Analyzed']}\n"
        f"- Identical functions: {digest['Identical Functions']}\n"
        f"- New functions: {digest['New Functions']}\n"
        f"- Changed functions (sim < 1.0, excluding NEW): {digest['Changed Functions (sim < 1.0, excluding NEW)']}\n"
        f"- Changed matched functions: {digest['Changed Matched Functions']}\n"
        f"- Changed unmatched functions: {digest['Changed Unmatched Functions']}"
        f"- TEE: true"
        f"- Hardening: {format_checksec_summary(checksec_props)}"
    )

    os.unlink(tmp1.name)
    os.unlink(tmp2.name)

    return digest, formatted_summary

def decompile_dex_and_diff(dex_path1, dex_path2):
    print("AAAAA\n")
    diff_result = subprocess.run(
            ["git", "diff", "--no-index", "--numstat", dex_path1, dex_path2],
            capture_output=True, text=True
        )

    #with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
    #    subprocess.run(["jadx", "-d", d1, dex_path1], check=True)
    #    subprocess.run(["jadx", "-d", d2, dex_path2], check=True)
#
    #    diff_result = subprocess.run(
    #        ["git", "diff", "--no-index", "--numstat", d1, d2],
    #        capture_output=True, text=True
    #    )
    #    return diff_result.stdout.strip()

def analyze_apk_diff(apk_path_1, apk_path_2):
    apk_diff_formatted_summary = {}
    tmp_dir1 = tempfile.mkdtemp(prefix="apk1_")
    tmp_dir2 = tempfile.mkdtemp(prefix="apk2_")
    try:
        subprocess.run(["unzip", "-q", apk_path_1, "-d", tmp_dir1], check=True)
        subprocess.run(["unzip", "-q", apk_path_2, "-d", tmp_dir2], check=True)

        diff_result = subprocess.run(
            ["git", "diff", "--no-index", "--numstat", tmp_dir1, tmp_dir2],
            capture_output=True, text=True
        )
        diff_output = diff_result.stdout.strip()

        tiered_changes = {
            "tier_1": [],
            "tier_2": [],
            "tier_3": [],
            "unclassified": []
        }
        dex_diff_outputs = {}

        for line in diff_result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            added, removed, path = parts
            
            raw_path = path.strip()          # Handle git rename/add/delete notation
            if "=>" in raw_path:
                # Convert Git-style brace expansion into two full paths
                match = re.search(r'^(.*){(.+?) => (.+?)}(.*)$', raw_path)
                if match:
                    prefix, src_mid, dst_mid, suffix = match.groups()
                    src_path = f"{prefix}{src_mid}{suffix}".strip()
                    dst_path = f"{prefix}{dst_mid}{suffix}".strip()
                else:
                    # Fallback in case of other style like {file => dev/null}
                    parts = raw_path.strip("{}").split("=>")
                    src_path = parts[0].strip()
                    dst_path = parts[1].strip()

                if "dev/null" in src_path:
                    rel_path = dst_path.split("/", 1)[-1]
                    change_type = "added"
                elif "dev/null" in dst_path:
                    rel_path = src_path.split("/", 1)[-1]
                    change_type = "deleted"
                else:
                    rel_path = dst_path.split("/", 1)[-1]
                    change_type = "modified"
            else:
                rel_path = raw_path.split("/", 1)[-1] if "/" in raw_path else raw_path
                change_type = "modified"

            if not rel_path or rel_path.lower() == "null":
                continue

            tier = categorize_path(rel_path)
            change_entry = {
                "file": rel_path,
                "added": added,
                "removed": removed,
                "change_type": change_type
            }

            normalized_rel_path = normalize_rel_path(rel_path)

            #if "classes" in rel_path and rel_path.endswith(".dex"):
            if "classes" in rel_path and rel_path.endswith(".dex") and change_type == "modified":
                #print("WAnt to decompile")
                dex_path1 = os.path.join(tmp_dir1, normalized_rel_path)
                dex_path2 = os.path.join(tmp_dir2, normalized_rel_path)
                #print("Dex path1: ", dex_path1)
                #print("Dex path2: ", dex_path2)
                #print("APK path1: ", apk_path_1)
                #print("APK path2: ", apk_path_2)
                if os.path.exists(dex_path1) and os.path.exists(dex_path2):
                    try:
                        print("Decompiling ", dex_path1, " and ", dex_path2)
                        dex_diff_outputs[rel_path] = decompile_dex_and_diff(dex_path1, dex_path2)
                    except subprocess.CalledProcessError as e:
                        #pass
                        dex_diff_outputs[rel_path] = f"Decompilation error: {str(e)}"
            
            if tier != "tier_3":
                tiered_changes[tier].append(change_entry)

        has_meaningful_diff = any(tiered_changes[t] for t in ["tier_1", "tier_2"])

        if has_meaningful_diff:
            apk_diff_formatted_summary = {
                "apk": os.path.basename(apk_path_1),
                "priv-app": "priv-app" in apk_path_1,
                "changes": tiered_changes,
                "dex_diffs": dex_diff_outputs
            }

        manifest_changed = any("AndroidManifest.xml" in line for line in diff_output.splitlines())
        manifest_status = "AndroidManifest.xml changed: yes" if manifest_changed else "AndroidManifest.xml changed: no"

        return diff_output + "\n\n" + manifest_status, apk_diff_formatted_summary
    except subprocess.CalledProcessError as e:
        apk_diff_formatted_summary = {
            "apk": os.path.basename(apk_path_1),
            "priv-app": "priv-app" in apk_path_1,
            "error": f"Error processing APK diff: {e}"
        }
        return f"Error processing APK diff: {e}", apk_diff_formatted_summary
    finally:
        shutil.rmtree(tmp_dir1)
        shutil.rmtree(tmp_dir2)

#def analyze_shared_lib_or_bin(path, so_path_1, so_path_2, rc_bin_paths, rc_libs, so_match):
#    is_shared_lib = so_match is not None
#    lib_or_bin_name = basename(so_path_2)
#
#    checksec_props = radigest.compare_checksec_properties(so_path_1, so_path_2)
#    similarity, distance = radigest.get_similarity_and_distance(so_path_1, so_path_2)
#    summary = radigest.parse_function_diffs(so_path_1, so_path_2)
#    total = summary["total_functions"]
#    changed = summary["changed"]
#
#    digest = {
#        "Similarity Score": round(similarity, 3),
#        "Radiff2 Distance": distance,
#        "Total Functions Analyzed": total,
#        "Identical Functions": summary['identical'],
#        "New Functions": summary['new'],
#        "Changed Functions (sim < 1.0, excluding NEW)": changed,
#        "Changed Matched Functions": summary['changed matched'],
#        "Changed Unmatched Functions": summary['changed unmatched'],
#        "Mentioned in .rc": lib_or_bin_name == "init",
#        "TEE": False,
#        "Hardening comparison": checksec_props
#    }
#
#    mentioned_in_rc = "true" if lib_or_bin_name == "init" else "false"
#    if is_shared_lib:
#        if lib_or_bin_name in rc_libs:
#            digest["Mentioned in .rc"] = True
#            digest["Used By"] = [os.path.basename(p) for p in rc_libs[lib_or_bin_name]]
#            mentioned_in_rc = "true"
#    else:
#        matched_rc_bin = any(p.endswith(so_path_2) for p in rc_bin_paths)
#        if matched_rc_bin:
#            digest["Mentioned in .rc"] = True
#            mentioned_in_rc = "true"
#
#    formatted_summary = (
#        f"Similarity Score: {similarity:.3f}\n"
#        f"Radiff2 Distance: {distance}\n"
#        f"Total functions analyzed: {total}\n"
#        f"- Identical functions: {summary['identical']} ({summary['identical'] / total:.1%})\n"
#        f"- New functions: {summary['new']} ({summary['new'] / total:.1%})\n"
#        f"- Changed functions (sim < 1.0, excluding NEW): {changed} ({changed / total:.1%})\n"
#        f"- Changed matched functions: {summary['changed matched']} ({summary['changed matched'] / total:.1%})\n"
#        f"- Changed unmatched functions: {summary['changed unmatched']} ({summary['changed unmatched'] / total:.1%})"
#        f"- TEE: False"
#        f"- Hardening: {format_checksec_summary(checksec_props)}"
#    )
#
#    return digest, formatted_summary + "\nMentioned in rc:" + mentioned_in_rc

def analyze_shared_lib_or_bin(path, so_path_1, so_path_2, rc_bin_json, rc_libs, so_match):
    is_shared_lib = so_match is not None
    lib_or_bin_name = basename(so_path_2)
    #print(rc_bin_json)

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
        "Mentioned in .rc": lib_or_bin_name == "init",  # default fallback
        "TEE": False,
        "Hardening comparison": checksec_props
    }

    # Mentioned in .rc flag & metadata tracking
    rc_metadata = None
    mentioned_in_rc = False

    if is_shared_lib:
        if lib_or_bin_name in rc_libs:
            digest["Mentioned in .rc"] = True
            digest["Used By"] = [os.path.basename(p) for p in rc_libs[lib_or_bin_name]]
            mentioned_in_rc = True
    else:
        so_path_str = os.path.abspath(str(so_path_2))
        print("SO PATH ABS: ", so_path_str)
        if so_path_str in rc_bin_json:
            print("BIN MENTIONED IN RC")
            digest["Mentioned in .rc"] = True
            rc_metadata = rc_bin_json[so_path_str]
            digest["rc_metadata"] = rc_metadata
            mentioned_in_rc = True

    # Start summary
    formatted_summary = (
        f"Similarity Score: {similarity:.3f}\n"
        f"Radiff2 Distance: {distance}\n"
        f"Total functions analyzed: {total}\n"
        f"- Identical functions: {summary['identical']} ({summary['identical'] / total:.1%})\n"
        f"- New functions: {summary['new']} ({summary['new'] / total:.1%})\n"
        f"- Changed functions (sim < 1.0, excluding NEW): {changed} ({changed / total:.1%})\n"
        f"- Changed matched functions: {summary['changed matched']} ({summary['changed matched'] / total:.1%})\n"
        f"- Changed unmatched functions: {summary['changed unmatched']} ({summary['changed unmatched'] / total:.1%})\n"
        f"- TEE: False\n"
    )

    # Add .rc metadata if available
    if mentioned_in_rc:
        if rc_metadata:
            rc_info = []
            for field in ("user", "group", "capabilities"):
                if field in rc_metadata:
                    value = rc_metadata[field]
                    if isinstance(value, list):
                        value = ", ".join(value)
                    rc_info.append(f"{field}: {value}")
            if rc_info:
                formatted_summary += "- .rc metadata: " + "; ".join(rc_info) + "\n"
        elif is_shared_lib:
            formatted_summary += "- Mentioned in rc via shared lib usage\n"

    # Add hardening summary
    formatted_summary += format_checksec_summary(checksec_props)

    return digest, formatted_summary


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
    formatted_apk_digests = {}

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

                if apk_match:
                    apk_path_1, apk_path_2 = reconstruct_paths(path)
                    #extra_analysis, apk_digest = analyze_apk_diff(apk_path_1, apk_path_2) #TODO: bring back!!!
                    apk_digest={}
                    if apk_digest != {}:
                        formatted_apk_digests[extract_tail_path(apk_path_1, 4)] = apk_digest
                
                elif "tee" in path:
                    ta1_path, ta2_path = reconstruct_paths(path)
                    print("TEE1: ", ta1_path, "TEE2: ", ta2_path)
                    if is_tee_trusted_app(ta2_path):
                        print("Is trusted app!")
                        digest, formatted_summary = analyze_tee_trusted_app(path, ta1_path, ta2_path, rc_bin_paths)
                        formatted_digests[extract_tail_path(ta2_path, 4)] = digest
                        extra_analysis = formatted_summary
                    elif looks_encrypted(ta2_path):
                        print("Looks enctypted!")
                        digest = {"TEE" : True, "Obfuscated" : True }
                        formatted_digests[extract_tail_path(ta2_path, 4)] = digest
                        extra_analysis = "TEE: true;\n Obfuscated: true"


                elif so_match or radigest.is_executable_elf(so_path_2):
                    digest, extra_analysis = analyze_shared_lib_or_bin(path, so_path_1, so_path_2, rc_bin_paths, rc_libs, so_match)
                    formatted_digests[extract_tail_path(so_path_2, 4)] = digest

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
    
    with open("shiba-oct-nov-23-bins.json", "w") as f:
        json.dump(formatted_digests, f, indent=2)
    
    with open("shiba-oct-nov-23-apks.json", "w") as f:
        json.dump(formatted_apk_digests, f, indent=2)

    root["__renamed__"] = renamed_files
    return root

def dump_json(filename, bins_in_rc, elf_libs_file, topmost_key = None):
    diff_text = open(filename, "r").read()

    full_rc_bin_paths = []
    rc_libs = {}
    #with open(bins_in_rc, "r") as f:
    #    for line in f:
    #        binary_path = line.strip()
    #        if not binary_path:
    #            continue
    #        full_rc_bin_paths.append(binary_path)
    #print(full_rc_bin_paths)
    #print("-------------------------------------------------")

    with open(bins_in_rc) as f:
        full_rc_bin_paths = json.load(f)

    with open(elf_libs_file) as f:
        rc_libs = json.load(f)
    #print(rc_libs)
    #print("-------------------------------------------------")

    
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
    with open("shiba-oct-nov2023.json", "w") as f:
        f.write(res)
