#!/usr/bin/env python3
import sys
import json
from collections import defaultdict
from os.path import basename

def load_visibility_data(path):
    with open(path) as f:
        raw = json.load(f)

    result = defaultdict(dict)  # app_name -> {(type, name): (exported, permission)}
    for full_apk_path, components in raw.items():
        app_name = basename(full_apk_path)
        for comp in components:
            key = (comp["type"], comp["name"])
            result[app_name][key] = (comp["exported"], comp["permission"])
    return result

def compare_visibility(old, new):
    increased = []
    decreased = []

    common_apps = set(old.keys()) & set(new.keys())
    for app in common_apps:
        old_components = old[app]
        new_components = new[app]

        for comp_key in old_components:
            if comp_key in new_components:
                old_exported, _ = old_components[comp_key]
                new_exported, _ = new_components[comp_key]

                if old_exported != new_exported:
                    change = {
                        "app": app,
                        "component": {
                            "type": comp_key[0],
                            "name": comp_key[1]
                        },
                        "from": old_exported,
                        "to": new_exported
                    }
                    if old_exported == "false" and new_exported == "true":
                        increased.append(change)
                    elif old_exported == "true" and new_exported == "false":
                        decreased.append(change)

    return {
        "increased_visibility": increased,
        "decreased_visibility": decreased
    }

def main():
    if len(sys.argv) != 4:
        print("Usage: 4_visibility_digest.py <old.json> <new.json> <outfile>")
        sys.exit(1)

    old_path, new_path, outfile = sys.argv[1], sys.argv[2], sys.argv[3]
    old_data = load_visibility_data(old_path)
    new_data = load_visibility_data(new_path)

    result = compare_visibility(old_data, new_data)
    #print(json.dumps(result, indent=2))
    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    main()
