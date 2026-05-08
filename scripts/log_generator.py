# log_generator.py
import time, random
from datetime import datetime
import os

# change path if needed
LOG_PATH = os.path.join("..", "logs", "auth_dummy.log")  # scripts folder -> ../logs

# Real public IPs from USA, Australia, Europe, Asia
ips = ["8.8.8.8", "1.1.1.1", "91.198.174.192", "103.76.181.180", "197.210.65.196"]
msgs = [
    "Failed password for invalid user admin from {ip} port 22 ssh2",
    "Accepted password for user from {ip} port {port} ssh2",
    "Failed password for root from {ip} port 22 ssh2",
    "IN=eth0 SRC={ip} DST=192.0.2.1 ... DPT={port}"
]

def write_line(line):
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")
    print("WROTE:", line)

def main():
    print("Starting log generator. Writing to:", LOG_PATH)
    while True:
        ip = random.choice(ips)
        port = random.choice([22, 23, 80, 443, 8080, 3306])
        template = random.choice(msgs)
        line = f"{datetime.now().strftime('%b %d %H:%M:%S')} server sshd: " + template.format(ip=ip, port=port)
        write_line(line)
        time.sleep(random.choice([1,2,2,3]))  # short delay

if __name__ == "__main__":
    main()
