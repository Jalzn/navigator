import json, os, shutil, socket, subprocess, sys, tempfile, time

scenario = sys.argv[1]
parent, child = socket.socketpair()
arm = {"type":"ARM", "point":"after_fsync" if scenario == "after" else "before_append",
       "messageId":"11"*16, "deliveryAttemptId":"12"*16}
if scenario == "mismatch": arm["messageId"] = "ff"*16
if scenario == "malformed": parent.sendall(b'{bad}\n')
elif scenario == "noncanonical": parent.sendall((json.dumps(arm)+"\n").encode())
else:
    parent.sendall((json.dumps(arm, separators=(",", ":"))+"\n").encode())
    if scenario == "duplicate": parent.sendall((json.dumps(arm, separators=(",", ":"))+"\n").encode())
worker = os.path.join(os.path.dirname(__file__), "journal-fault-worker.ts")
directory = tempfile.mkdtemp(prefix="navigator-fault-")
journal = os.path.join(directory, "journal")
proc = subprocess.Popen([shutil.which("node"), "--import", "tsx", worker, str(child.fileno()), journal],
                        pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
child.close()
if scenario in ("before", "after", "duplicate", "timeout", "trailing"):
    parent.settimeout(2)
    reached = json.loads(parent.makefile().readline())
    assert reached["type"] == "REACHED" and "payload" not in reached
    records = open(journal).readlines()
    assert len(records) == (1 if scenario in ("before", "duplicate", "trailing", "timeout") else 2)
    if scenario in ("before", "after"): parent.sendall(b'{"type":"RELEASE"}\n')
    elif scenario == "trailing": parent.sendall(b'{"type":"RELEASE"}\n{"type":"RELEASE"}\n')
    elif scenario == "timeout": time.sleep(5.2)
if scenario == "mismatch": time.sleep(.1)
code = proc.wait(timeout=7)
stderr = proc.stderr.read().decode()
expected = 0 if scenario in ("before", "after", "mismatch") else 1
assert code == expected, (code, stderr)
