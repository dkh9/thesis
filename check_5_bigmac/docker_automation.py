import sys
import os
import pexpect
import re 
import time
import threading
import json


container = "bigmac-container"
policy = "F54_2024"
vendor = "samsung"

ipy_prompt = re.compile(r"In \[(\d+)\]:")  # Matches In [n]:

def run_prolog_print(child, timeout=180):
    child.sendline("print")
    output_lines = []
    start_time = time.time()

    while True:
        try:
            idx = child.expect([r"query \[.*?\]>", r".+\r?\n"], timeout=5)
            if idx == 0:
                break  # We hit the prompt — done
            line = child.match.group(0).strip()
            if line != "print" and not re.match(r"query \[.*?\]>", line):
                output_lines.append(line)
        except pexpect.TIMEOUT:
            if time.time() - start_time > timeout:
                print("[!] Timeout while collecting 'print' output")
                break

    return "\n".join(output_lines)

def dump_process_dict_to_jsonl(process_dict, output_path):
    with open(output_path, 'w') as f:
        for k, v in process_dict.items():
            json_line = json.dumps({k: v})
            f.write(json_line + "\n")

def extract_process_dict(text):
    """
    Parses the inst.processes output and returns a dictionary mapping
    each process key to the string representation of the ProcessNode.
    """
    process_dict = {}

    # Trim the 'Out[n]:' line if it exists
    text = re.sub(r'^Out\[\d+\]:', '', text, flags=re.MULTILINE).strip()

    # Remove outer dict braces if present
    if text.startswith('{') and text.endswith('}'):
        text = text[1:-1]

    # Match key-value pairs, accounting for nested angle brackets
    pattern = re.compile(r"""
        \s*'(?P<key>[^']+)':      # Match the key
        \s*<(?P<value>            # Start capturing the full ProcessNode
            ProcessNode[^>]*      # Initial ProcessNode and part of content
            (?:>[^>]*<[^>]*?)*    # Allow nested angle brackets (greedy pair-wise matching)
        )>                        # Final closing bracket
    """, re.VERBOSE)

    for match in pattern.finditer(text):
        key = match.group('key')
        value = f"<{match.group('value')}>"
        process_dict[key] = value

    return process_dict


def quit_docker(child):
    child.sendline("exit")
    child.close()
    print('done')

def wait_for_ipy_prompt(child):
    child.expect(ipy_prompt)
    prompt_num = int(child.match.group(1))
    return prompt_num

def run_ipy_command(child, cmd, timeout=30):
    prompt_num = wait_for_ipy_prompt(child)  # Wait for In [n]:
    child.sendline(cmd)
    next_prompt = f"In [{prompt_num + 1}]:"
    try:
        child.expect(re.escape(next_prompt), timeout=timeout)
        output = child.before
        # Extract Out[n]: block if present
        out_match = re.search(rf"Out\[{prompt_num}\]:\s*\n?(.*)", output, re.DOTALL)
        return out_match.group(1).strip() if out_match else output.strip()
    except pexpect.TIMEOUT:
        print(f"[!] Timeout while waiting for IPython prompt after: {cmd}")
        return None

def periodic_status_message(stop_event, interval=10):
    while not stop_event.is_set():
        print("Extraction in process...")
        stop_event.wait(interval)

def extract_fw(vendor, archive, child):
    cmd = f"sudo venv/bin/python extract.py --vendor {vendor} --user hexhive {archive}"

    # Start background progress printer
    stop_event = threading.Event()
    printer_thread = threading.Thread(target=periodic_status_message, args=(stop_event,))
    printer_thread.start()

    try:
        out = run_command(child, cmd, prompt=r"\(venv\).*?\$", timeout=720)
    finally:
        stop_event.set()         # Stop the printer
        printer_thread.join()    # Wait for thread to clean up

    return out

def get_paths(child, query):
    print(f"[+] Running query: {query}")
    child.sendline(query)
    child.expect(r"query \[.*?\]>", timeout=360)
    query_output = child.before.strip()
    if "ERROR" in query_output:
        print("ERROR! Going onto the next:")
        return ""
    else:
        print("Query result:")
        print(query_output)
        print("-------------------")
        time.sleep(3)
        print("[+] Running print")
        paths = run_prolog_print(child)
        print("Extracted paths:")
        print(paths)
        return paths

def run_command(child, cmd, prompt=r"\$", timeout=30):
    child.sendline(cmd)
    try:
        child.expect(prompt, timeout=timeout)
        output = child.before.strip()
        lines = output.splitlines()
        if lines and lines[0].strip() == cmd.strip():
            lines = lines[1:]  # skip the echoed command
        return "\n".join(lines)
    except pexpect.TIMEOUT:
        print(f"[!] Timeout while waiting for marker after command: {cmd}")
        return None

def main():
    if len(sys.argv) != 8:
        print("Usage: docker_automation.py [extract|process] <zip> <vendor> <outfile> <sys_serv> <uapps> <network_stack>")
        sys.exit(1)

    operation, archive, vendor, outfile, ssfile, uapps_file, ns_file = sys.argv[1:]
    
    
    if operation not in ("extract", "process"):
        print("Unsupported op:", operation)
        sys.exit(1)

    print("SPAWNING SHELL")
    child = pexpect.spawn(f"docker exec -it -u dcl {container} bash", encoding="utf-8")
    child.expect(r"\$")
    out = run_command(child, "cd /opt/BigMAC/BigMAC")
    out = run_command(child, "source venv/bin/activate", prompt=r"\(venv\).*?\$")
    policy = os.path.splitext(os.path.basename(archive))[0]
    out = extract_fw(vendor, archive, child)

    if "INFO: Saving extracted information" in out:
        print(" Finished extracting.")
    else:
        print("SOmething is wrong: ", out)
    
    extract_path = f"extract/{vendor}/{policy}"
    archive_path = os.path.abspath(archive)

    
    print("Saving the policy...")
    cmd = f"venv/bin/python ./process.py --vendor {vendor} {policy} --save"
    out = run_command(child, cmd, prompt=r"\(venv\).*?\$", timeout=720)
    if "Finished instantiating SEPolicy" in out:
        print("Successfully saved the policy!")
        cmd = f"sudo rm -rf {extract_path}"
        out = run_command(child, cmd, prompt=r"\$", timeout=30)
        if not os.path.exists(f"{extract_path}"):
            print("Extract dir deleted: SUCCESS")
        else:
            print("Extract dir deleted: FAIL")
        cmd = f"sudo rm -rf {archive}"
        out = run_command(child, cmd, prompt=r"\$", timeout=30)
        if not os.path.exists(archive_path):
            print("Archive deleted: SUCCESS")
        else:
            print("Archive deleted: FAIL (Still exists at:", archive_path, ")")
    else:
        print("Failed at saving the policy!")
        quit_docker(child)

    time.sleep(3)
    
    out = run_command(child, f"venv/bin/python ./process.py --vendor {vendor} {policy} --load --debug", prompt=r"In \[\d+\]:", timeout=180)
    print("OUT AFTER WAITING FOR PROLOG:")
    print(out)

    out = run_ipy_command(child, "inst.processes")
    print("Extracted processes")
    process_dict = extract_process_dict(out)

    print("Quitting...")
    out = run_command(child, "quit", prompt=r"\(venv\).*?\$", timeout=120)

    uapps = []
    sys_server = []
    network_stack = []
    for key in process_dict.keys():
        if "untrusted_app" in key:
            uapps.append(key)
        elif "system_server" in key:
            sys_server.append(key)
        elif "network_stack" in key:
            network_stack.append(key)
    
    print("UAPPS: ", uapps)
    print("SYTEM SERVER: ", sys_server)
    print("NETWORK STACK: ", network_stack)

#-------------------------------------------------------------------------------------------

    print("Loading prolog prompt...")
    out = run_command(child, f"sudo venv/bin/python ./process.py --vendor {vendor} {policy} --load --prolog", prompt=r"query \[.*?\]>", timeout=480)
    print("B4 sleep")
    time.sleep(3)
    print("Going into server")

    server_out = ""
    uapp_out = ""
    network_out = ""

    for server in sys_server:
        query = f"query _ process:{server} 2"
        paths = get_paths(child, query)
        server_out += paths
    
    for uapp in uapps:
        query = f"query process:{uapp} _ 2"
        paths = get_paths(child, query)
        uapp_out += paths

    for ns in network_stack:
        query = f"query _ process:{ns} 2"
        paths = get_paths(child, query)
        network_out += paths

    out = run_command(child, "quit", prompt=r"\(venv\).*?\$", timeout=120)
    quit_docker(child)

    with open(ssfile, "w") as f:
        f.write(server_out)
    
    with open(uapps_file, "w") as f:
        f.write(uapp_out)
    
    with open(ns_file, "w") as f:
        f.write(network_out)

#ssfile, uapps_file, ns_file
    dump_process_dict_to_jsonl(process_dict, outfile)

if __name__ == "__main__":
    main()