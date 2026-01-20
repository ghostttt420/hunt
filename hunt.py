import os
import sys
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- TARGETS ---
# We focus on the file with the constants and the main API definition
TARGET_CLASSES = ["ApiConstantKt", "Api"]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try:
        requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Analyzing {apk_path}...")
    try:
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        report_lines = []
        report_lines.append(f"🔓 **Value Extractor Report: {package}**")

        for dex in dex_list:
            for current_class in dex.get_classes():
                class_name = current_class.get_name()
                clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')

                if clean_name in TARGET_CLASSES:
                    report_lines.append(f"\n📂 **File: {clean_name}**")
                    
                    # METHOD 1: Get Static Constant Values (The "Easy" Way)
                    # Kotlin 'const val' are stored in the field definition
                    for field in current_class.get_fields():
                        field_name = field.get_name()
                        init_value = field.get_init_value()
                        
                        # We only want the interesting fields
                        if init_value and "API_" in field_name:
                            # .get_value() extracts the actual string
                            val = init_value.get_value()
                            if isinstance(val, str):
                                report_lines.append(f"  🔑 {field_name} = \"{val}\"")
                    
                    # METHOD 2: Get Base URLs from the 'Api' class
                    # Sometimes URLs are stored as fields named "BASE_URL" or "HOST"
                    if clean_name == "Api":
                        for field in current_class.get_fields():
                            init_value = field.get_init_value()
                            if init_value:
                                val = init_value.get_value()
                                if isinstance(val, str) and "http" in val:
                                    report_lines.append(f"  🌐 {field.get_name()} = \"{val}\"")

        # Send Report (Chunked if too long)
        full_text = "\n".join(report_lines)
        if len(full_text) > 4000:
            # Send first 4000 chars (most important stuff usually at top)
            send_telegram_alert(full_text[:4000])
            print(full_text[:4000] + "\n...[truncated]")
        else:
            send_telegram_alert(full_text)
            print(full_text)

    except Exception as e:
        err_msg = f"⚠️ Error: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
