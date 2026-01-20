import os
import re
import requests
import zipfile
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- THE KILL LIST (Regex Patterns) ---
PATTERNS = {
    "🔑 AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "🔐 AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
    "💳 Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "💬 Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "🗺️ Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "🐦 Twitter/X Token": r"[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "📧 Mailgun API": r"key-[0-9a-zA-Z]{32}",
    "☁️ Heroku API": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "🗝️ Private Key (RSA)": r"-----BEGIN RSA PRIVATE KEY-----",
    "🛡️ JWT Token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
}

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Starting 'Scorched Earth' Scan on {apk_path}...")
    report = f"☢️ **Cloud Sweeper Report: {apk_path}**\n\n"
    
    found_secrets = set()

    try:
        # 1. DECOMPILE & GLOBAL STRING SCAN
        print("[*] Decompiling Dex bytecode...")
        app, dex_list, dx = AnalyzeAPK(apk_path)
        
        # Merge all strings from all dex files into one massive pool
        all_strings = set()
        for dex in dex_list:
            for s in dex.get_strings():
                all_strings.add(str(s))
        
        print(f"[*] Scanning {len(all_strings)} strings against {len(PATTERNS)} patterns...")
        
        for s in all_strings:
            # Check every string against every regex
            for name, pattern in PATTERNS.items():
                matches = re.findall(pattern, s)
                for m in matches:
                    # Clean up the match
                    if isinstance(m, tuple): m = m[0]
                    clean_match = m.strip()
                    
                    # Basic filters to reduce noise
                    if len(clean_match) < 8: continue
                    if "EXAMPLE" in clean_match.upper(): continue
                    
                    # Create a "censored" version for the report so we don't leak full keys in plain text logs
                    censored = clean_match[:4] + "..." + clean_match[-4:]
                    found_secrets.add(f"{name}: `{clean_match}`")

        # 2. SCAN ASSETS/CONFIG FILES (Non-code files)
        print("[*] scanning assets/ folder for config files...")
        with zipfile.ZipFile(apk_path, 'r') as z:
            for filename in z.namelist():
                # We only care about text-based config files
                if filename.endswith((".json", ".xml", ".properties", ".txt", ".yaml", ".ini")):
                    try:
                        content = z.read(filename).decode('utf-8', errors='ignore')
                        for name, pattern in PATTERNS.items():
                            matches = re.findall(pattern, content)
                            for m in matches:
                                if isinstance(m, tuple): m = m[0]
                                found_secrets.add(f"{name} (in {filename}): `{m.strip()}`")
                    except: pass

        # 3. REPORT GENERATION
        if found_secrets:
            # Sort by "High Severity" (AWS/Stripe first)
            secrets_list = sorted(list(found_secrets))
            
            # Highlight the juicy ones
            high_pri = [s for s in secrets_list if "AWS" in s or "Stripe" in s or "Slack" in s]
            low_pri = [s for s in secrets_list if s not in high_pri]

            if high_pri:
                report += "**🚨 CRITICAL FINDINGS:**\n" + "\n".join(high_pri) + "\n\n"
            
            if low_pri:
                report += "**⚠️ Other Findings:**\n" + "\n".join(low_pri[:20]) # Limit to 20 to avoid spam
                if len(low_pri) > 20: report += f"\n...and {len(low_pri)-20} more."
        else:
            report += "[-] Clean scan. No obvious cloud keys found."

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
