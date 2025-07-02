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
    parts = [p.strip() for p in level_string.split('|')]
    if not parts:
        return 0

    base = parts[0]
    flags = parts[1:] if len(parts) > 1 else []

    base_val = base_score.get(base, 0)
    flag_val = sum(flag_weights.get(f, 0) for f in flags)

    return base_val + flag_val

def load_jsonl_scores(path):
    scores = {}
    with open(path) as f:
        for line in f:
            entry = json.loads(line)
            scores[entry["permission_name"]] = score_level(entry["protection_level"])
    return scores

def load_protection_diff(path):
    with open(path) as f:
        summary = json.load(f)
    return {
        "increased": {entry["permission_name"] for entry in summary.get("increased", [])},
        "decreased": {entry["permission_name"] for entry in summary.get("decreased", [])}
    }

def compare_gids(old, new, scores, diff_summary):
    result = {"increased": [], "decreased": []}
    all_gids = set(old) | set(new)

    for gid in all_gids:
        old_perms = set(old.get(gid, []))
        new_perms = set(new.get(gid, []))

        if old_perms != new_perms:
            perms_union = old_perms | new_perms
            for perm in perms_union:
                old_score = scores.get(perm, 0) if perm in old_perms else None
                new_score = scores.get(perm, 0) if perm in new_perms else None
                if old_score is not None and new_score is not None:
                    if new_score > old_score:
                        result["increased"].append({
                            "gid": gid,
                            "permission": perm,
                            "change": f"{old_score} → {new_score}"
                        })
                    elif new_score < old_score:
                        result["decreased"].append({
                            "gid": gid,
                            "permission": perm,
                            "change": f"{old_score} → {new_score}"
                        })
        else:
            for perm in new_perms:
                if perm in diff_summary["increased"]:
                    result["increased"].append({
                        "gid": gid,
                        "permission": perm,
                        "change": "protection_level ↑"
                    })
                elif perm in diff_summary["decreased"]:
                    result["decreased"].append({
                        "gid": gid,
                        "permission": perm,
                        "change": "protection_level ↓"
                    })
    return result

# --- Main ---
if len(sys.argv) != 5:
    print("Usage: compare_gid_permissions.py old.json new.json permissions.jsonl protection_diff_summary.json")
    sys.exit(1)

old_json, new_json, perm_jsonl, diff_json = sys.argv[1:]

old_gid_map = load_json(old_json)
new_gid_map = load_json(new_json)
perm_scores = load_jsonl_scores(perm_jsonl)
diff_summary = load_protection_diff(diff_json)

summary = compare_gids(old_gid_map, new_gid_map, perm_scores, diff_summary)

with open("gid_permission_diff_summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print("Summary written to gid_permission_diff_summary.json")