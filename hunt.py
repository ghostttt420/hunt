import os
import sys
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- SECRET SIGNATURES (The Trap) ---
# We use Regex to identify specific key formats
SIGNATURES = {
    # 1. Cloud Infrastructure (Critical)
    "🚨 AWS Access Key": r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])",
    "🚨 AWS Secret": r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "🚨 Google Cloud Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "🚨 Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    
    # 2. Payment & Business (Money)
    "💰 Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "💰 PayPal Client": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "💰 Square Access": r"sq0atp-[0-9A-Za-z\-_]{22}",
    
    # 3. Communication (SMS/Chat)
    "💬 Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})?",
    "💬 Twilio SID": r"AC[a-f0-9]{32}",
    "💬 Telegram Bot": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
    
    # 4. Generic "High Entropy" (Catch-all for weird keys)
    # Looks for strings that say "secret", "key", or "token" followed by a long random string
    "⚠️ Generic Secret": r"(?i)(api_key|access_token|secret_key|auth_token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{32,})['\"]?",
}

# Ignore list to prevent false alarms (like public libraries)
IGNORE_STRINGS = [
    "example.com", "android.intent", "www.w3.org", "google.com", 
    "facebook.com", "github.com", "googleapis.com", "crashlytics"
]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    # Telegram has a limit, so we chunk long messages
    if len(message) > 4000:
        message = message[:4000] + "\n...[TRUNCATED]"
        
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try:
        requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Hunting Secrets in {apk_path}...")
    try:
        # Decompile the APK
        app, dex_list, dx = AnalyzeAPK(apk_path)
        package = app.get_package()
        
        found_secrets = []
        
        # 1. HARVEST ALL STRINGS
        # We combine every string in the app into one massive text block for scanning
        print("[*] Extracting strings...")
        all_strings = set()
        for dex in dex_list:
            for s in dex.get_strings():
                if len(s) > 8: # Ignore tiny strings
                    all_strings.add(str(s))
        
        # Add Resources strings (like strings.xml)
        try:
            res = app.get_android_resources()
            if res:
                res_strings = res.get_strings_resources()
                # Use a safer way to extract values from the resource object
                for key in res_strings:
                     # This handles different androguard versions
                    try:
                        all_strings.add(str(res_strings[key])) 
                    except: pass
        except: pass

        print(f"[*] Scanning {len(all_strings)} unique strings...")

        # 2. MATCH SIGNATURES
        for s in all_strings:
            # Quick filter: Ignore common junk
            if any(ign in s for ign in IGNORE_STRINGS):
                continue
                
            for name, pattern in SIGNATURES.items():
                # Regex Search
                matches = re.findall(pattern, s)
                if matches:
                    for match in matches:
                        # If the match is a tuple (from groups), join it
                        if isinstance(match, tuple):
                            match = match[-1] # Usually the last group is the key
                        
                        # formatting
                        found_secrets.append(f"{name}:\n`{match}`")

        # 3. REPORTING
        # Remove duplicates
        found_secrets = list(set(found_secrets))
        
        if found_secrets:
            found_secrets.sort()
            report = f"🗝️ **Key Hunter Report: {package}**\n\n"
            report += "\n\n".join(found_secrets)
            
            print(report)
            send_telegram_alert(report)
        else:
            print("[-] No high-value keys found.")

    except Exception as e:
        err_msg = f"⚠️ Scan Error: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
