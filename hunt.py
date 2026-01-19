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
    # 1. The API URL (We verify it's still there)
    "API Host": r"login\.ohmconnect\.com",
    
    # 2. JSON Parameters (The input fields)
    # We look for quoted strings often used in JSON logic
    "Possible Param": r"\"(email|password|user_id|userid|token|auth|device_id|mac|serial|code)\"",
    
    # 3. HTTP Headers (The authorization info)
    "Header": r"\"(Authorization|Bearer|X-API-Key|Content-Type)\"",
}

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    requests.post(url, data=data)

def analyze_apk(apk_path):
    print(f"[*] Analyzing {apk_path}...")
    try:
        app = APK(apk_path)
        package = app.get_package()
        
        # Get all strings
        all_strings = ""
        for dex in app.get_all_dex():
            try:
                for s in dex.get_strings(): all_strings += str(s) + "\n"
            except: pass

        found_params = []
        found_headers = []

        # Hunt for Parameters
        matches = list(set(re.findall(PATTERNS["Possible Param"], all_strings)))
        for match in matches:
            found_params.append(f"🔹 Param: {match}")
            
        # Hunt for Headers
        matches = list(set(re.findall(PATTERNS["Header"], all_strings)))
        for match in matches:
            found_headers.append(f"🔸 Header: {match}")

        # Reporting
        if found_params or found_headers:
            report = f"🕵️ **API Skeleton Report: {package}**\n\n"
            report += "**Potential JSON Inputs:**\n"
            report += "\n".join(sorted(found_params))
            report += "\n\n**Headers:**\n"
            report += "\n".join(sorted(found_headers))
            
            print(report)
            send_telegram_alert(report)
        else:
            print("[-] No obvious API parameters found.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
