import re
import json
import argparse

def parse_checker_output(path):
    status_map = {}
    config_line_pattern = re.compile(r'^(CONFIG_\S+|\S+CONFIG_\S+)\s+\|.*?\|\s+(OK|FAIL)')

    with open(path) as f:
        for line in f:
            match = config_line_pattern.match(line.strip())
            if match:
                config, status = match.groups()
                config = config.strip()
                status_map[config] = status
    return status_map

def compare_configs(before_map, after_map):
    changes = {
        "ok_to_fail": [],
        "fail_to_ok": []
    }

    all_configs = set(before_map) | set(after_map)
    for cfg in all_configs:
        before = before_map.get(cfg)
        after = after_map.get(cfg)
        if before == "OK" and after == "FAIL":
            changes["ok_to_fail"].append({"option": cfg, "change": "OK ->FAIL"})
        elif before == "FAIL" and after == "OK":
            changes["fail_to_ok"].append({"option": cfg, "change": "FAIL -> OK"})
    return changes

def main():
    parser = argparse.ArgumentParser(description="Diff kernel-hardening-checker outputs.")
    parser.add_argument("before_file", help="Path to BEFORE output file")
    parser.add_argument("after_file", help="Path to AFTER output file")
    args = parser.parse_args()

    before_status = parse_checker_output(args.before_file)
    after_status = parse_checker_output(args.after_file)
    changes = compare_configs(before_status, after_status)

    print(json.dumps(changes, indent=2))

if __name__ == "__main__":
    main()
