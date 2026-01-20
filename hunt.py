import os
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    # Chunking just in case
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Starting Global Grep on {apk_path}...")
    try:
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        found_commands = set()
        
        print("[*] Scanning DEX files for API strings...")
        for dex in dex_list:
            for s in dex.get_strings():
                # We are looking for API-like strings (dots) containing our keywords
                if "upgrade" in s or "ota" in s or "firmware" in s:
                    # Filter for API patterns (must have dots, usually starts with tuya/thing)
                    if "." in s and len(s) < 100:
                        found_commands.add(s)

        # REPORT
        report = f"🔎 **API Command Hunter: {package}**\n\n"
        
        # Sort and filter
        commands = sorted(list(found_commands))
        
        # Prioritize the most likely ones (starting with tuya or thing)
        high_priority = [c for c in commands if c.startswith("tuya") or c.startswith("thing")]
        others = [c for c in commands if c not in high_priority]
        
        if high_priority:
            report += "**🔥 High Probability:**\n"
            report += "\n".join([f"`{c}`" for c in high_priority])
            report += "\n\n"
            
        if others:
            report += "**❓ Others:**\n"
            # Limit 'others' to avoid spamming
            report += "\n".join([f"`{c}`" for c in others[:20]])

        print(report)
        send_telegram_alert(report)

    except Exception as e:
        err_msg = f"⚠️ Scan Failed: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
