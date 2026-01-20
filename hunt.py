import os
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- PATTERNS ---
# We are looking for hardcoded cloud storage links
PATTERNS = {
    "📦 Firmware Binary": r"https?://[\w./-]+\.bin",
    "📦 Zip Archive": r"https?://[\w./-]+\.zip",
    "🔄 Tuya/Ohm Upgrade": r"https?://[\w./-]+(?:upgrade|ota|firmware|airtake)[\w./-]*",
}

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    # Send in chunks if needed, but this report should be short
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Starting URL Sniper on {apk_path}...")
    try:
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        # 1. HARVEST ALL STRINGS
        print("[*] Extracting strings...")
        all_strings = set()
        
        # Get strings from code (DEX)
        for dex in dex_list:
            for s in dex.get_strings():
                if len(s) > 10: # Ignore tiny noise
                    all_strings.add(str(s))
        
        # Get strings from resources (XML)
        try:
            res = app.get_android_resources()
            if res:
                res_strings = res.get_strings_resources()
                for key in res_strings:
                    try: all_strings.add(str(res_strings[key])) 
                    except: pass
        except: pass

        # 2. SCAN FOR URLS
        found_urls = []
        for s in all_strings:
            for name, pattern in PATTERNS.items():
                matches = re.findall(pattern, s)
                for match in matches:
                    # Filter junk (e.g., standard android URLs)
                    if "android.com" in match or "w3.org" in match: continue
                    found_urls.append(f"🔹 {name}:\n{match}")

        # 3. REPORT
        found_urls = sorted(list(set(found_urls))) # Remove duplicates
        
        if found_urls:
            report = f"🎯 **Firmware URL Sniper: {package}**\n\n"
            report += "\n\n".join(found_urls[:20]) # Top 20 results
            print(report)
            send_telegram_alert(report)
        else:
            msg = f"[-] No direct Firmware URLs found in {package}."
            print(msg)
            send_telegram_alert(msg)

    except Exception as e:
        err_msg = f"⚠️ Scan Failed: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
