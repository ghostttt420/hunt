import os
import sys
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

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
        # Load the APK
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        print(f"[*] Hunting for Login Models in {package}...")
        
        found_classes = []

        # Scan every class name in the app
        for dex in dex_list:
            for method in dex.get_methods():
                class_name = method.get_class_name()
                
                # CLEANUP: Convert "Lcom/ohm/plug/LoginRequest;" -> "LoginRequest"
                clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')
                
                # FILTER: Only keep classes related to Auth/Login/User
                # We also exclude standard Android libraries to reduce noise
                if any(x in clean_name for x in ["Login", "Auth", "Token", "User", "Session", "Credential"]):
                    if "android" not in class_name and "google" not in class_name:
                        found_classes.append(clean_name)

        # Remove duplicates and sort
        found_classes = sorted(list(set(found_classes)))
        
        if found_classes:
            report = f"🎯 **Login Sniper Report**\n\n"
            # Show the top 20 most relevant login files
            report += "\n".join(found_classes[:25])
            
            print(report)
            send_telegram_alert(report)
        else:
            print("[-] No specific Login classes found.")

    except Exception as e:
        err_msg = f"⚠️ Critical Error: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
