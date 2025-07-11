import sys
import os
import pexpect
import re 
import time
import threading


container = "bigmac-container"
policy = "F54_2024"
vendor = "samsung"


def periodic_status_message(stop_event, interval=10):
    while not stop_event.is_set():
        print("Extraction in process...")
        stop_event.wait(interval)

def extract_fw(vendor, archive, child):
    cmd = f"sudo venv/bin/python extract.py --vendor {vendor} --user dcl {archive}"

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

def run_ipy_command(child, cmd, timeout=30):
    child.sendline(cmd)
    try:
        child.expect(r"In \[\d+\]:", timeout=timeout)
        output = child.before.strip()
        return output
    except pexpect.TIMEOUT:
        print(f"[!] Timeout while waiting for IPython prompt after: {cmd}")
        return None

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



#cmd = f"sudo venv/bin/python ./process.py --debug --vendor {vendor} {policy} --load --prolog"
#
## Run the BigMAC processing script
#child.sendline(cmd)
#
## Wait for either IPython or an error
#index = child.expect([
#    r"In \[\d+\]:",  # IPython prompt
#    r"ERROR: Policy directory does not exist",
#], timeout=60)
##
### Output from the process startup
##print("\n<<< Output before detection:")
#print("out4: ")
##
#if index == 0:
#    print("✅ IPython shell detected!")
#    output = run_ipy_command("inst.processes")
#    print("\n<<< Output of processes:")
#    print(output)
#    run_ipy_command("quit")
#    run_command("quit")
#
#elif index == 1:
#    print("❌ Policy directory missing or unreadable.")
#
#
#
def main():
    if len(sys.argv) != 5:
        print("Usage: docker_automation.py [extract|process] <zip> <vendor> <outfile>")
        sys.exit(1)

    operation, archive, vendor, outfile = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    
    
    if operation not in ("extract", "process"):
        print("Unsupported op:", operation)
        sys.exit(1)

    print("SPAWNING SHELL")
    child = pexpect.spawn(f"docker exec -it -u dcl {container} bash", encoding="utf-8")
    child.expect(r"\$")
    out = run_command(child, "cd /opt/BigMAC/BigMAC")
    out = run_command(child, "source venv/bin/activate", prompt=r"\(venv\).*?\$")
    out = extract_fw(vendor, archive, child)
    print("AFTER EXTRACTION: ")
    print(out)

    if "INFO: Saving extracted information" in out:
        print(" Finished extracting.")

        policy = os.path.splitext(os.path.basename(archive))[0]
        extract_path = f"extract/{vendor}/{policy}"
        archive_path = os.path.abspath(archive)
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


    child.sendline("exit")
    child.close()
    print('done')
    #venv/bin/python extract.py --vendor samsung --user dcl 20250526205751.zip'''

if __name__ == "__main__":
    main()