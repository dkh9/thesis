import json

def is_fully_identical(entry):
    return entry.get("Identical Functions") == entry.get("Total Functions Analyzed")

def has_capabilities(entry):
    return bool(entry.get("rc_metadata", {}).get("capabilities"))

def is_root_user_or_group(entry):
    rc = entry.get("rc_metadata", {})
    return rc.get("user") == "root" or rc.get("group") == "root"

# Load JSON file
with open("../shiba-oct-nov-23-bins.json") as f:
    data = json.load(f)

# Separate fully identical entries
identical_entries = {k: v for k, v in data.items() if is_fully_identical(v)}
non_identical_entries = [(k, v) for k, v in data.items() if not is_fully_identical(v)]

# Now apply stable sorts in reverse order of priority
# So the most important sort is applied last

# 1. Similarity Score (lowest first)
non_identical_entries.sort(key=lambda kv: kv[1].get("Similarity Score", 1.0))

# 2. Hardening comparison: non-identical → goes to top
non_identical_entries.sort(key=lambda kv: kv[1].get("Hardening comparison", {}).get("identical", True))

# 3. TEE = True → goes to top
non_identical_entries.sort(key=lambda kv: not kv[1].get("TEE", False))

# 4. Mentioned in .rc → True goes to top
non_identical_entries.sort(key=lambda kv: not kv[1].get("Mentioned in .rc", False))

# 5. Capabilities present → goes to top
non_identical_entries.sort(key=lambda kv: not has_capabilities(kv[1]))

# 6. user or group is root → goes to top
non_identical_entries.sort(key=lambda kv: not is_root_user_or_group(kv[1]))

# Now combine with the untouched identical entries at the end
sorted_combined = {k: v for k, v in non_identical_entries + list(identical_entries.items())}

# Write output
with open("sorted_bin_output.json", "w") as f:
    json.dump(sorted_combined, f, indent=2)

print("Sorted JSON written to sorted_bin_output.json")
