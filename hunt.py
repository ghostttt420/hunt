import os
import sys
import re
import requests
# 1. We switch to the high-level helper to avoid import errors
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- BROAD PATTERNS ---
PATTERNS = {
    # API & Login
    "API Key Candidate": r"(?i)\b(apikey|auth_token|access_token|client_secret)\b",
    "Login Param": r"(?i)\b(username|password|email|passwd|user_id|userid|credential)\b",
    
    # Hardware
    "Hardware Param": r"(?i)\b(mac_address|serial_no|device_id|tuya_id|local_key)\b",
    
    # API Structure
    "HTTP Method": r"\b(POST|GET|PUT|DELETE|PATCH)\b",
    "Content Type": r"application/(json|x-www-form-urlencoded|xml)",
}

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
        # 2. This ONE LINE does everything:
        # app = The APK object (info)
        # dex_list = List of parsed Code objects (methods, strings)
        # dx = Analysis object (we ignore it for speed)
        app, dex_list, dx = AnalyzeAPK(apk_path)
        
        package = app.get_package()
        version = app.get_androidversion_name()
        print(f" -> Success! Scanned {package} v{version}")
        
        found_items = []

        # --- 1. STRING HUNTING ---
        print("[*] Scanning Strings...")
        all_strings = ""
        
        # dex_list already contains the parsed objects! No more 'bytes' errors.
        for dex in dex_list:
            for s in dex.get_strings():
                all_strings += str(s) + "\n"
                
        # Get strings from resources
        try:
            res = app.get_android_resources()
            if res: all_strings += str(res.get_strings_resources())
        except: pass

        # Scan strings against patterns
        for name, pattern in PATTERNS.items():
            matches = list(set(re.findall(pattern, all_strings)))
            # Filter huge junk strings
            clean_matches = [m for m in matches if len(m) < 40] 
            for match in clean_matches:
                found_items.append(f"🔹 {match} ({name})")

        # --- 2. CLASS NAME HUNTING ---
        print("[*] Scanning Class Names...")
        for dex in dex_list:
            for method in dex.get_methods():
                class_name = method.get_class_name()
                # Look for "Request", "Response", "Model"
                if any(x in class_name for x in ["Request", "Response", "Model", "DTO"]):
                    # Clean up: Lcom/ohm/LoginRequest; -> LoginRequest
                    clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')
                    if "android" not in clean_name and "google" not in clean_name:
                        found_items.append(f"📂 Class: {clean_name}")

        # Remove duplicates
        found_items = list(set(found_items))
        
        # Reporting
        if found_items:
            found_items.sort()
            report = f"🧪 **Deep Dredge Report: {package}**\n\n"
            # Telegram Limit Protection
            report += "\n".join(found_items[:35])
            
            print(report)
            send_telegram_alert(report)
        else:
            print("[-] Deep scan found nothing. App might be heavily obfuscated.")

    except Exception as e:
        err_msg = f"⚠️ Critical Error: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
