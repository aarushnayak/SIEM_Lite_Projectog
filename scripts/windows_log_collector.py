# windows_log_collector.py (Final version with winevt-ng)
import os
import time
from datetime import datetime
import xml.etree.ElementTree as ET
import winevt.evapi as wevt # Humari sahi, modern library

# --- Constants aur Paths ---
BASE_DIR = os.path.dirname(__file__)
LOG_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "auth_dummy.log"))

# --- Helper Function ---
def write_line(line):
    # auth_dummy.log file mein nayi line likho
    with open(LOG_PATH, "a", encoding='utf-8') as f:
        f.write(line + "\n")
    print("WROTE:", line)

# --- Main Logic ---
def main():
    print("Starting Windows Log Collector (winevt-ng). Monitoring 'Security' events...")
    
    log_channel = 'Security'
    # Hum sirf Login events (ID 4625 for failed, 4624 for success) dekhenge
    query = "*[System[EventID=4625 or EventID=4624]]"

    # Live, naye events ke liye subscribe karo
    subscription = wevt.EvtSubscribe(
        log_channel,
        wevt.EvtSubscribeFlags.EvtSubscribeToFutureEvents,
        Query=query
    )

    while True:
        try:
            # Naye events ka intezaar karo
            events = wevt.EvtNext(subscription, 1)
            if not events:
                time.sleep(0.5)
                continue

            for event in events:
                xml_data = wevt.EvtRender(event, wevt.EvtRenderFlags.EvtRenderEventXml)
                root = ET.fromstring(xml_data)
                ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                
                event_id = root.find('.//e:System/e:EventID', ns).text
                
                # IP Address dhoondo
                ip_address = "127.0.0.1" # Default agar IP na mile
                ip_element = root.find(".//e:EventData/e:Data[@Name='IpAddress']", ns)
                if ip_element is not None and ip_element.text not in ('-', '::1'):
                    ip_address = ip_element.text
                
                # Action decide karo
                action_text = "Unknown Login Event"
                if event_id == '4625':
                    action_text = f"Failed password for user from {ip_address}"
                elif event_id == '4624':
                    action_text = f"Accepted password for user from {ip_address}"

                # Humare SIEM ke format mein line banao
                ts = datetime.now().strftime('%b %d %H:%M:%S')
                formatted_line = f"{ts} windows_security: {action_text}"
                
                # Line ko auth_dummy.log mein likh do
                write_line(formatted_line)

        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(2)

if __name__ == "__main__":
    try:
        print("IMPORTANT: This script must be run with Administrator privileges.")
        main()
    except KeyboardInterrupt:
        print("\nStopping Windows Log Collector.")