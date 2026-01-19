import os
import sys
import re
import requests
from androguard.core.apk import APK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- PATTERNS ---
PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Generic API Key": r"(?i)(api_key|apikey|secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,45})",
    "Tuya Local Key": r"[a-zA-Z0-9]{16}", 
    "Private IP Address": r"192\.168\.[0-9]{1,3}\.[0-9]{1,3}",
    "Firmware URL": r"https?://.*\.bin",
    "Staging/Dev URL": r"https://[a-z0-9-]*staging[a-z0-9-]*\.",
    "OhmConnect API": r"api\.ohmconnect\.com/[a-z0-9/]+",
}

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Telegram credentials not set.")
        return
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
        print("[*] Telegram alert sent!")
    except Exception as e:
        print(f"[!] Failed to send Telegram: {e}")

def find_apks():
    apk_list = []
    # Walk through all folders (recursively) to find .apk files
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.endswith(".apk"):
                apk_list.append(os.path.join(root, file))
    return apk_list

def analyze_apk(apk_path):
    print(f"[*] Analyzing {apk_path}...")
    try:
        app = APK(apk_path)
        package_name = app.get_package()
        version = app.get_androidversion_name()
        
        print(f" -> Package: {package_name} v{version}")
        
        # Extract strings
        all_strings = ""
        for dex in app.get_all_dex():
            try:
                for s in dex.get_strings():
                    all_strings += str(s)
            except: pass
                
        try:
            res = app.get_android_resources()
            if res: all_strings += str(res.get_strings_resources())
        except: pass

        # Hunt
       found_secrets = []
        # specific "trash words" that appear in your screenshot
        ignore_list = ["Sheet", "View", "Label", "Layout", "google", "Format", "select", "Input"]

        for name, pattern in PATTERNS.items():
            matches = list(set(re.findall(pattern, all_strings)))
            for match in matches:
                # 1. Filter out common words (Noise reduction)
                if any(word in match for word in ignore_list):
                    continue
                
                # 2. Heuristic: Real keys usually have digits AND letters
                # If it's just letters (like "BottomSheetBehav"), it's probably code, not a key
                if name == "Tuya Local Key" and match.isalpha():
                    continue

                if len(match) > 5 and "example" not in match:
                    found_secrets.append(f"🔴 {name}: {match}")

        if found_secrets:
            report = f"🚨 **Hunter Report: {package_name} v{version}**\n\n"
            report += "\n".join(found_secrets[:15])
            print(report)
            send_telegram_alert(report)
        else:
            print(f"[-] No obvious secrets found in v{version}.")
            # Uncomment next line if you want a ping even when nothing is found
            # send_telegram_alert(f"✅ Scan finished for {package_name}. No secrets found.")

    except Exception as e:
        err_msg = f"⚠️ Error analyzing {apk_path}: {str(e)}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = find_apks()
    if files:
        print(f"[*] Found {len(files)} APKs: {files}")
        analyze_apk(files[0])
    else:
        msg = "❌ Error: No APK file found after download step."
        print(msg)
        # Now we alert you if the download failed
        send_telegram_alert(msg)
