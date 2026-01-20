import os
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- TARGETS ---
# We are looking for the specific file that handles OTA (Firmware) requests
TARGET_CLASSES = [
    "AccessoriesOTARequestRep", 
    "ActionOtaResponse", 
    "UpgradeApi",
    "ThingOta"
]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Analyzing {apk_path} for OTA Commands...")
    try:
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        report = f"🕵️‍♂️ **Command Extraction Report**\n"
        
        for dex in dex_list:
            for current_class in dex.get_classes():
                class_name = current_class.get_name()
                clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')
                
                # Only inspect our suspects
                if any(t in clean_name for t in TARGET_CLASSES):
                    report += f"\n📂 **File: {clean_name}**"
                    
                    # 1. Grab all strings defined in this class
                    # This is where "tuya.m.device.upgrade" would be hidden
                    const_strings = set()
                    for method in current_class.get_methods():
                        if method.get_code():
                            for instr in method.get_code().get_bc().get_instructions():
                                output = instr.get_output()
                                if '"' in output:
                                    # Extract string inside quotes
                                    s = output.split('"')[1]
                                    if len(s) > 5 and ("." in s or "upgrade" in s):
                                        const_strings.add(s)
                    
                    if const_strings:
                        for s in const_strings:
                            report += f"\n  🔑 Found String: `{s}`"
                    else:
                        report += "\n  (No suspicious strings found)"

        print(report)
        send_telegram_alert(report)

    except Exception as e:
        err = f"⚠️ Error: {e}"
        print(err)
        send_telegram_alert(err)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
