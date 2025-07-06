#!/usr/bin/env python3
import sys
import json

# Base protection levels (dominant scores)
base_score = {
    "normal": 10,
    "dangerous": 20,
    "signature": 30,
    "signatureOrSystem": 30,  # Deprecated but same meaning
    "internal": 40            # Rare and undocumented
}

# Flag weights (minor modifiers)
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
        return base_score["normal"]  # Default to "normal" if unspecified

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

def get_permission_set(component_entry):
    return set(component_entry.values())

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
                old_perms = get_permission_set(old_entries.get(comp_name, {}))
                new_perms = get_permission_set(new_entries.get(comp_name, {}))

                def total_score(perms):
                    return sum(score_level(perm_levels.get(p, "normal")) for p in perms)

                old_score = total_score(old_perms)
                new_score = total_score(new_perms)

                if old_perms != new_perms:
                    if new_score > old_score:
                        result["increased"].append({
                            "apk": apk,
                            "component": comp_name,
                            "type": comp_type,
                            "change": f"score {old_score} -> {new_score}",
                            "added_permissions": sorted(list(new_perms - old_perms)),
                            "removed_permissions": sorted(list(old_perms - new_perms))
                        })
                    elif new_score < old_score:
                        result["decreased"].append({
                            "apk": apk,
                            "component": comp_name,
                            "type": comp_type,
                            "change": f"score {old_score} -> {new_score}",
                            "added_permissions": sorted(list(new_perms - old_perms)),
                            "removed_permissions": sorted(list(old_perms - new_perms))
                        })
                else:
                    for perm in new_perms:
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
                                            "change": f"score {old_score} -> {new_score}"
                                        })
                                    elif new_score < old_score:
                                        result["decreased"].append({
                                            "apk": apk,
                                            "component": comp_name,
                                            "type": comp_type,
                                            "permission": perm,
                                            "change": f"score {old_score} -> {new_score}"
                                        })
                                    break

    return result

# --- Main ---
if len(sys.argv) != 5:
    print("Usage: 5_component_visibility_diff.py old.json new.json permissions.jsonl protection_diff_summary.json")
    sys.exit(1)

old_json, new_json, perm_jsonl, diff_json = sys.argv[1:]

old_component_map = load_json(old_json)
new_component_map = load_json(new_json)
perm_levels = load_jsonl_levels(perm_jsonl)
diff_summary = load_protection_diff(diff_json)

summary = compare_components(old_component_map, new_component_map, perm_levels, diff_summary)

with open("5_component_visibility_digest.json", "w") as f:
    json.dump(summary, f, indent=2)

print("Summary written to 5_component_visibility_digest.json")
