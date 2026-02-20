#!/usr/bin/env python3
import json, re, time, pathlib


eventfile = "/var/log/suricata/eve.json"
output = "/home/peyton/Documents/block.txt"
flags = re.compile(("ET SCAN|Nmap|Suspicious inbound"),re.I)

def readline(path):
    with open(path, "r") as f:
        f.seek(0,2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(.5)
                continue
            yield line

for line in readline(eventfile):
    event = json.loads(line)
    if event.get("event_type") !='alert':
        continue
    signature = event["alert"]["signature"]
    src = event["src_ip"]
    timestamp = event["timestamp"]
    with open(output, "a") as o:
        o.write("Time: "+timestamp+ " Event source: " + src + " Event Signature: " + signature + "\n")