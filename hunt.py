import os
import sys
import re
import requests
from androguard.core.apk import APK
# NEW IMPORT: This is required to translate raw bytes into code
from androguard.core.bytecodes.dvm import DalvikVMFormat

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- BROAD PATTERNS (The "Deep Dredge") ---
PATTERNS = {
    # 1. API Related Words (Case Insensitive)
    "API Key Candidate": r"(?i)\b(apikey|auth_token|access_token|client_secret)\b",
    "Login Param": r"(?i)\b(username|password|email|passwd|user_id|userid|credential)\b",
    "Hardware Param": r"(?i)\b(mac_address|serial_no|device_id|tuya_id|local_key)\b",
    
    # 2. HTTP Methods
    "HTTP Method": r"\b(POST|GET|PUT|DELETE|PATCH)\b",
    
    # 3. Content Types
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
        app = APK(apk_path)
        package = app.get_package()
        
        found_items = []
        
        # --- PRE-PROCESS: Convert Bytes to Code Objects ---
        dex_objects = []
        for dex_bytes in app.get_all_dex():
            try:
                # This fixes the "bytes has no attribute" error
                dex_objects.append(DalvikVMFormat(dex_bytes))
            except Exception as e:
                print(f"[-] Failed to parse a DEX file: {e}")

        # --- 1. STRING HUNTING ---
        print("[*] Scanning Strings...")
        all_strings = ""
        
        # Get strings from the NOW PROCESSED code objects
        for dex in dex_objects:
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
            clean_matches = [m for m in matches if len(m) < 40] # Filter huge junk
            for match in clean_matches:
                found_items.append(f"🔹 {match} ({name})")

        # --- 2. CLASS NAME HUNTING ---
        print("[*] Scanning Class Names...")
        for dex in dex_objects:
            for method in dex.get_methods():
                class_name = method.get_class_name()
                # Look for "Request", "Response", "Model" in the file path
                if any(x in class_name for x in ["Request", "Response", "Model", "DTO"]):
                    # Clean up the name (Lcom/ohm/plug/LoginRequest; -> LoginRequest)
                    clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')
                    if "android" not in clean_name and "google" not in clean_name:
                        found_items.append(f"📂 Class: {clean_name}")

        # Remove duplicates
        found_items = list(set(found_items))
        
        # Reporting
        if found_items:
            found_items.sort()
            report = f"🧪 **Deep Dredge Report: {package}**\n\n"
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
