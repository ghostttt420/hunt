import os
import sys
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- SPAM FILTER ---
# We will ignore any file containing these words
IGNORE_LIST = [
    "Facebook", "Instagram", "Google", "Android", "AccessToken", 
    "Fragment", "Activity", "View", "Wrapper", "Factory", "Impl",
    "Interceptor", "Manager", "Builder"
]

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
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        print(f"[*] Hunting for Custom Models in {package}...")
        
        found_classes = []

        for dex in dex_list:
            for method in dex.get_methods():
                class_name = method.get_class_name()
                
                # CLEANUP: Lcom/ohm/plug/LoginRequest; -> LoginRequest
                clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')
                
                # FILTER 1: Remove Noise
                if any(ignored in clean_name for ignored in IGNORE_LIST):
                    continue
                
                # FILTER 2: Find the "Good Stuff"
                # We want API Models (Requests/Responses) or API Services
                if any(x in clean_name for x in ["Request", "Response", "Body", "Service", "Api"]):
                    
                    # Heuristic: Custom code usually doesn't have "$" symbols (inner classes)
                    if "$" not in clean_name:
                        found_classes.append(clean_name)

        # Remove duplicates and sort
        found_classes = sorted(list(set(found_classes)))
        
        if found_classes:
            report = f"💎 **Cleaned Code Report**\n\n"
            # Show top 30 non-Facebook results
            report += "\n".join(found_classes[:30])
            
            print(report)
            send_telegram_alert(report)
        else:
            print("[-] No relevant classes found after filtering.")

    except Exception as e:
        print(f"Error: {e}")
        send_telegram_alert(f"Error: {e}")

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
