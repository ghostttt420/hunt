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
    "Tuya Local Key": r"[a-fA-F0-9]{16}", # Refined: Only Hex characters
    "Firebase DB": r"https://[a-z0-9-]+\.firebaseio\.com", # Specific Firebase hunter
    "OhmConnect API": r"https://login\.ohmconnect\.com/[a-zA-Z0-9/_\-]+",
}

IGNORE_LIST = ["example", "google", "support", "www"]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    requests.post(url, data=data)

def check_firebase_security(url):
    """Ethically checks if a Firebase DB is public."""
    try:
        # We add 'shallow=true' to avoid downloading data. We just want the status code.
        target = f"{url}/.json?shallow=true"
        response = requests.get(target, timeout=5)
        
        if response.status_code == 200:
            return f"⚠️ **VULNERABLE (OPEN):** {url}"
        elif response.status_code == 401:
            return f"🔒 **SECURE (LOCKED):** {url}"
        else:
            return f"❓ Status {response.status_code}: {url}"
    except:
        return f"❌ Error connecting to {url}"

def analyze_apk(apk_path):
    print(f"[*] Analyzing {apk_path}...")
    try:
        app = APK(apk_path)
        package = app.get_package()
        version = app.get_androidversion_name()
        
        # Get all strings
        all_strings = ""
        for dex in app.get_all_dex():
            try:
                for s in dex.get_strings(): all_strings += str(s) + "\n"
            except: pass
        try:
            res = app.get_android_resources()
            if res: all_strings += str(res.get_strings_resources())
        except: pass

        found_secrets = []
        firebase_urls = []

        for name, pattern in PATTERNS.items():
            matches = list(set(re.findall(pattern, all_strings)))
            for match in matches:
                if any(bad in match for bad in IGNORE_LIST): continue
                
                # Logic Filters
                if name == "Tuya Local Key":
                    # Real keys are usually lowercase hex
                    if not re.match(r'^[a-f0-9]{16}$', match): continue
                
                if name == "Firebase DB":
                    firebase_urls.append(match)
                    continue # We handle this separately below

                found_secrets.append(f"🔹 {name}: {match}")

        # CHECK FIREBASE STATUS
        if firebase_urls:
            found_secrets.append("\n🔥 **Firebase Security Check:**")
            for url in firebase_urls:
                status = check_firebase_security(url)
                found_secrets.append(status)

        # Reporting
        if found_secrets:
            report = f"🚨 **Hunter Report: {package} v{version}**\n\n"
            report += "\n".join(found_secrets[:25])
            print(report)
            send_telegram_alert(report)
        else:
            print("[-] No secrets found.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
