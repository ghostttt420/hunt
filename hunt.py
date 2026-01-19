import os
import sys
import re
import requests
from androguard.core.bytecodes.apk import APK

# --- CONFIGURATION ---
# 1. Get your Chat ID by messaging @userinfobot on Telegram
# 2. Get your Bot Token from @BotFather
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- CUSTOM SEARCH PATTERNS FOR OHMPLUG ---
PATTERNS = {
    # Cloud & API Keys
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Generic API Key": r"(?i)(api_key|apikey|secret)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{32,45})",
    
    # Specific to Smart Plugs (Tuya/Local Hooks)
    "Tuya Local Key": r"[a-zA-Z0-9]{16}", 
    "Private IP Address": r"192\.168\.[0-9]{1,3}\.[0-9]{1,3}",
    "Firmware URL": r"https?://.*\.bin",
    
    # Specific to OhmConnect (Financial/Staging)
    "Staging/Dev URL": r"https://[a-z0-9-]*staging[a-z0-9-]*\.",
    "OhmConnect API": r"api\.ohmconnect\.com/[a-z0-9/]+",
}

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Telegram credentials not set. Skipping alert.")
        return
    
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
        print("[*] Telegram alert sent!")
    except Exception as e:
        print(f"[!] Failed to send Telegram: {e}")

def analyze_apk(apk_path):
    print(f"[*] Analyzing {apk_path}...")
    
    try:
        app = APK(apk_path)
        package_name = app.get_package()
        version = app.get_androidversion_name()
        
        print(f" -> Package: {package_name}")
        print(f" -> Version: {version}")
        
        # Extract all text strings from the app (code + layout files)
        all_strings = ""
        for dex in app.get_all_dex():
            all_strings += str(dex.get_strings())
        all_strings += str(app.get_android_resources().get_strings_resources())

        # Hunt for secrets
        found_secrets = []
        for name, pattern in PATTERNS.items():
            # Find unique matches
            matches = list(set(re.findall(pattern, all_strings)))
            for match in matches:
                # Filter out false positives (too short or common words)
                if len(match) > 5 and "example" not in match:
                    found_secrets.append(f"🔴 {name}: {match}")

        # Reporting
        if found_secrets:
            report = f"🚨 **Hunter Report: {package_name} v{version}**\n\n"
            report += "\n".join(found_secrets[:15]) # Limit to 15 items to avoid spam
            
            print(report)
            send_telegram_alert(report)
            return True
        else:
            print(f"[-] No obvious secrets found in v{version}.")
            return False

    except Exception as e:
        err_msg = f"⚠️ Error analyzing {apk_path}: {str(e)}"
        print(err_msg)
        send_telegram_alert(err_msg)
        return False

if __name__ == "__main__":
    # Auto-detect APK in folder
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files:
        analyze_apk(files[0])
    else:
        print("No APK found in directory.")
