#!/usr/bin/env python3
import sys
import argparse
import xml.etree.ElementTree as ET
import json
import os

ANDROID_NS = 'http://schemas.android.com/apk/res/android'

def get_attr(elem, attr_name):
    return elem.attrib.get(f'{{{ANDROID_NS}}}{attr_name}')

def extract_permissions_from_stdin(manifest_text, apk_path):
    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError as e:
        print(f"Failed to parse manifest for {apk_path}: {e}", file=sys.stderr)
        return None

    app = root.find("application")
    if app is None:
        return None

    app_permission = get_attr(app, 'permission')
    component_tags = ['activity', 'service', 'receiver', 'provider']
    permission_keys = ['permission', 'readPermission', 'writePermission']

    # Initialize the nested structure
    result = {
        apk_path: {
            "components": {tag: {} for tag in component_tags}
        }
    }

    for tag in component_tags:
        for comp in app.findall(tag):
            name = get_attr(comp, 'name')
            if not name:
                continue

            permissions = {
                key: get_attr(comp, key) for key in permission_keys if get_attr(comp, key)
            }

            # Only activity, service, and receiver inherit app-level permission
            if tag in ['activity', 'service', 'receiver'] and 'permission' not in permissions and app_permission:
                permissions['permission'] = app_permission

            result[apk_path]["components"][tag][name] = permissions

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, help="Path to the source APK file")
    parser.add_argument("--outfile", required=True, help="Path to the output JSON file")
    args = parser.parse_args()

    manifest_text = sys.stdin.read()
    parsed = extract_permissions_from_stdin(manifest_text, args.apk)

    if not parsed:
        sys.exit(0)

    # Load existing data if the file exists
    if os.path.exists(args.outfile):
        try:
            with open(args.outfile, "r") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Failed to load existing JSON file: {e}", file=sys.stderr)
            data = {}
    else:
        data = {}

    # Add or update entry
    data.update(parsed)

    # Write back to the file
    with open(args.outfile, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Updated manifest permission info written to {args.outfile}")
