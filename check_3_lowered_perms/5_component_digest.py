#!/usr/bin/env python3
import sys
import json

# Base protection levels (dominant scores)
base_score = {
    "normal": 10,
    "dangerous": 20,
    "signature": 30,
    "signatureOrSystem": 30,
    "internal": 40
}

flag_weights = {
    "privileged": 5,
    "appop": 2,
    "runtime": 2,
    "instant": 1,
    "development": 1,
    "verifier": 1,
    "installer": 1,
    "preinstalled": 1,
    "vendorPrivileged": 3,
    "pre23": 0.5,
    "setup": 1,
    "oem": 1,
    "systemTextClassifier": 1,
    "documenter": 1
}

def score_level(level_string):
    if not level_string:
        return base_score["normal"]
    parts = [p.strip() for p in level_string.split('|') if p.strip()]
    base = None
    flags = []
    for part in parts:
        if part in base_score and base is None:
            base = part
        else:
            flags.append(part)
    base_val = base_score.get(base, base_score["normal"])
    flag_val = sum(flag_weights.get(f, 1) for f in flags)
    return base_val + flag_val

def load_json(path):
    with open(path) as f:
        return json.load(f)

def load_jsonl_levels(path):
    levels = {}
    with open(path) as f:
        for line in f:
            entry = json.loads(line)
            levels[entry["permission_name"]] = entry["protection_level"]
    return levels

def load_protection_diff(path):
    with open(path) as f:
        summary = json.load(f)
    return {
        "increased": summary.get("increased", []),
        "decreased": summary.get("decreased", [])
    }

def compare_components(old_map, new_map, perm_levels, diff_summary):
    result = {"increased": [], "decreased": []}
    component_types = ["activity", "service", "receiver", "provider"]
    all_apks = set(old_map.keys()) | set(new_map.keys())

    for apk in all_apks:
        old_components = old_map.get(apk, {}).get("components", {})
        new_components = new_map.get(apk, {}).get("components", {})

        for comp_type in component_types:
            old_entries = old_components.get(comp_type, {})
            new_entries = new_components.get(comp_type, {})
            all_keys = set(old_entries) | set(new_entries)

            for comp_name in all_keys:
                old_perms_dict = old_entries.get(comp_name, {})
                new_perms_dict = new_entries.get(comp_name, {})

                keys_union = set(old_perms_dict.keys()) | set(new_perms_dict.keys())

                for key in keys_union:
                    old_perm = old_perms_dict.get(key)
                    new_perm = new_perms_dict.get(key)

                    if old_perm != new_perm:
                        old_score = score_level(perm_levels.get(old_perm, "normal")) if old_perm else 0
                        new_score = score_level(perm_levels.get(new_perm, "normal")) if new_perm else 0

                        if new_perm and not old_perm:
                            result["increased"].append({
                                "apk": apk,
                                "component": comp_name,
                                "type": comp_type,
                                "permission_type": key,
                                "permission": new_perm,
                                "change": f"added with score {new_score}"
                            })
                        elif old_perm and not new_perm:
                            result["decreased"].append({
                                "apk": apk,
                                "component": comp_name,
                                "type": comp_type,
                                "permission_type": key,
                                "permission": old_perm,
                                "change": f"removed with score {old_score}"
                            })
                        elif new_score > old_score:
                            result["increased"].append({
                                "apk": apk,
                                "component": comp_name,
                                "type": comp_type,
                                "permission_type": key,
                                "permission": new_perm,
                                "change": f"score {old_score} -> {new_score}"
                            })
                        elif new_score < old_score:
                            result["decreased"].append({
                                "apk": apk,
                                "component": comp_name,
                                "type": comp_type,
                                "permission_type": key,
                                "permission": new_perm,
                                "change": f"score {old_score} -> {new_score}"
                            })

                # Check unchanged permissions for protection level updates
                for perm in set(new_perms_dict.values()):
                    for direction in ["increased", "decreased"]:
                        for entry in diff_summary[direction]:
                            if entry["permission_name"] == perm:
                                old_score = score_level(entry["old_level"])
                                new_score = score_level(entry["new_level"])
                                if new_score > old_score:
                                    result["increased"].append({
                                        "apk": apk,
                                        "component": comp_name,
                                        "type": comp_type,
                                        "permission": perm,
                                        "change": f"score {old_score} -> {new_score} (protection level change)"
                                    })
                                elif new_score < old_score:
                                    result["decreased"].append({
                                        "apk": apk,
                                        "component": comp_name,
                                        "type": comp_type,
                                        "permission": perm,
                                        "change": f"score {old_score} -> {new_score} (protection level change)"
                                    })
                                break

    return result

# --- Main ---
if len(sys.argv) != 6:
    print("Usage: 5_component_digest.py old.json new.json permissions.jsonl protection_diff_summary.json outfile.json")
    sys.exit(1)

old_json, new_json, perm_jsonl, diff_json, outfile = sys.argv[1:]

old_component_map = load_json(old_json)
new_component_map = load_json(new_json)
perm_levels = load_jsonl_levels(perm_jsonl)
diff_summary = load_protection_diff(diff_json)

summary = compare_components(old_component_map, new_component_map, perm_levels, diff_summary)

with open(outfile, "w") as f:
    json.dump(summary, f, indent=2)

print("Summary written to ", outfile)
