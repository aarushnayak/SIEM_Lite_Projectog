# log_generator_v2.py (A smarter log generator)
import time
import random
from datetime import datetime
import os
from faker import Faker  # Nayi library import ki

# Faker ko initialize karo
fake = Faker()

# --- Constants aur Paths ---
BASE_DIR = os.path.dirname(__file__)
LOG_PATH = os.path.abspath(os.path.join(
    BASE_DIR, "..", "logs", "auth_dummy.log"))

# --- Helper Function ---


def write_line(line):
    # Log file mein nayi line likho
    with open(LOG_PATH, "a", encoding='utf-8') as f:
        f.write(line + "\n")
    print("WROTE:", line)

# --- Main Generator Logic ---

def main():
    print("Starting Smart Log Generator v2.0. Writing to:", LOG_PATH)
    
    while True:
        event_type = random.choices(
            population=["login_fail", "login_success", "brute_force_attack"],
            weights=[0.5, 0.2, 0.3], # Har event ka chance
            k=1
        )[0]

        ts = datetime.now().strftime('%b %d %H:%M:%S')

        # Event ke hisaab se log generate karo
        if event_type == "brute_force_attack":
            # Ek hi IP se lagaatar failed attempts
            attacker_ip = "118.172.155.122" # Yeh ek jaani-maani bad IP hai (score 100)
            print(f"--- Simulating Brute-Force from {attacker_ip} ---")
            for _ in range(random.randint(5, 8)):
                log_msg = f"Failed password for invalid user admin from {attacker_ip} port 22 ssh2"
                line = f"{ts} server sshd: {log_msg}"
                write_line(line)
                time.sleep(random.uniform(0.5, 2))
            
            # YEH HISSA AB THEEK SE IF BLOCK KE ANDAR HAI
            # 20% chance hai ki attack successful ho jayega
            if random.random() < 0.2:
                log_msg = f"Accepted password for user admin from {attacker_ip} port 22 ssh2"
                line = f"{ts} server sshd: {log_msg}"
                write_line(line)

        elif event_type == "login_fail":
            # Ek random failed login
            ip = fake.ipv4_public()
            user = random.choice(["root", "admin", "user", fake.user_name()])
            log_msg = f"Failed password for {user} from {ip} port 22 ssh2"
            line = f"{ts} server sshd: {log_msg}"
            write_line(line)

        elif event_type == "login_success":
            # Ek random successful login
            ip = fake.ipv4_public()
            user = random.choice(["admin", "guest", fake.user_name()])
            log_msg = f"Accepted password for user {user} from {ip} port 22 ssh2"
            line = f"{ts} server sshd: {log_msg}"
            write_line(line)
        
        # Agle event se pehle thoda ruko
        time.sleep(random.uniform(1, 4))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopping the log generator.")
