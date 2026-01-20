import os
import sys
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- PATTERNS ---
# We are looking for URLs that point to firmware files or update servers
PATTERNS = {
    "📦 Firmware Binary": r"https?://[\w./-]+\.bin",
    "📦 Zip Archive": r"https?://[\w./-]+\.zip",
    "🔄 OTA/Upgrade URL": r"https?://[\w./-]+(?:upgrade|ota|firmware)[\w./-]*",
}

# --- TARGET CLASSES ---
# We specifically inspect these files for logic
TARGET_CLASSES = ["ActionOtaResponse", "Upgrade", "Ota", "Firmware"]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    # Chunking for Telegram limit
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Starting Firmware Heist on {apk_path}...")
    try:
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        report_lines = []
        report_lines.append(f"💿 **Firmware Heist: {package}**")

        # 1. SCAN SPECIFIC OTA CLASSES
        print("[*] Inspecting OTA Logic...")
        for dex in dex_list:
            for current_class in dex.get_classes():
                class_name = current_class.get_name()
                clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')
                
                # Check if this class is related to OTA
                if any(t in clean_name for t in TARGET_CLASSES):
                    report_lines.append(f"\n📂 **Class: {clean_name}**")
                    
                    # Extract variables (might be "downloadUrl" or "version")
                    for field in current_class.get_fields():
                        report_lines.append(f"  • {field.get_name()}")
                    
                    # Extract hardcoded strings inside this class
                    code = ""
                    for method in current_class.get_methods():
                        if method.get_code():
                            for instr in method.get_code().get_bc().get_instructions():
                                if '"' in instr.get_output():
                                    report_lines.append(f"  String: {instr.get_output().strip()}")

        # 2. GLOBAL STRING SCAN (The .bin Hunter)
        print("[*] Scanning for binary URLs...")
        all_strings = ""
        for dex in dex_list:
            for s in dex.get_strings():
                all_strings += str(s) + "\n"

        found_urls = []
        for name, pattern in PATTERNS.items():
            matches = list(set(re.findall(pattern, all_strings)))
            for match in matches:
                # Filter out short junk matches
                if len(match) > 15:
                    found_urls.append(f"🔹 {name}: {match}")

        if found_urls:
            report_lines.append("\n**🌍 Potential Firmware Links:**")
            report_lines.extend(sorted(found_urls))
        else:
            report_lines.append("\n[-] No direct .bin or .zip URLs found globally.")

        # 3. REPORT
        final_report = "\n".join(report_lines)
        print(final_report)
        send_telegram_alert(final_report)

    except Exception as e:
        err_msg = f"⚠️ Heist Failed: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
