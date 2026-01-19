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
    # 1. Cloud & API Keys
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    
    # 2. Tuya / Smart Plug Secrets
    "Tuya Local Key": r"[a-zA-Z0-9]{16}", 
    "Private IP": r"192\.168\.[0-9]{1,3}\.[0-9]{1,3}",
    
    # 3. HTTP Endpoints (NEW!)
    # Catches http:// or https:// followed by domains
    "API Endpoint": r"https?://[a-zA-Z0-9\.\-\_]+(?:/[a-zA-Z0-9\.\-\_]*)*",
}

# --- NOISE FILTER (Ignore these common junk strings) ---
IGNORE_LIST = [
    "schemas.android", "www.w3.org", "google.com", "facebook.com", 
    "github.com", "example.com", "googlesyndication", "cloudflare",
    "BottomSheet", "Recycler", "Layout", "View", "xml", "json"
]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Telegram credentials not set.")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    # disable_web_page_preview makes the chat cleaner
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try:
        requests.post(url, data=data)
        print("[*] Telegram alert sent!")
    except Exception as e:
        print(f"[!] Failed to send Telegram: {e}")

def find_apks():
    apk_list = []
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
        
        # Extract strings from Code (DEX) + Resources (XML)
        all_strings = ""
        for dex in app.get_all_dex():
            try:
                for s in dex.get_strings():
                    all_strings += str(s) + "\n"
            except: pass
        try:
            res = app.get_android_resources()
            if res: all_strings += str(res.get_strings_resources())
        except: pass

        # Hunt
        found_secrets = []
        for name, pattern in PATTERNS.items():
            matches = list(set(re.findall(pattern, all_strings)))
            for match in matches:
                # FILTER 1: Skip if it contains ignored words
                if any(ignored in match for ignored in IGNORE_LIST):
                    continue
                
                # FILTER 2: Logic Checks
                # Tuya Keys must have at least one digit (rejects "BottomSheetLayout")
                if name == "Tuya Local Key" and match.isalpha():
                    continue
                # API Endpoints must contain specific interesting domains
                if name == "API Endpoint":
                    # Only keep it if it looks like a custom backend (tuya, ohm, api, dev, staging)
                    if not any(k in match for k in ["tuya", "ohm", "api", "dev", "test", "stage", "admin"]):
                        continue

                if len(match) > 5:
                    found_secrets.append(f"🔹 {name}: {match}")

        # Reporting
        if found_secrets:
            # Sort them so URLs appear together
            found_secrets.sort()
            
            header = f"🚨 **Hunter Report: {package_name}**\n"
            # Telegram has a 4096 char limit, so we chunk it if huge
            message_body = "\n".join(found_secrets[:25]) 
            
            print(header + message_body)
            send_telegram_alert(header + message_body)
        else:
            print(f"[-] No interesting secrets found in v{version}.")

    except Exception as e:
        err_msg = f"⚠️ Error analyzing {apk_path}: {str(e)}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = find_apks()
    if files:
        analyze_apk(files[0])
    else:
        print("❌ No APK found.")
