import os
import zipfile
import re
import requests

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- PATTERNS ---
# We are hunting for the "Master Keys" that sign API requests
PATTERNS = {
    "🔑 App Key": r"(?i)(app_?key|client_?id)\":\s*\"([a-zA-Z0-9]{10,})\"",
    "🔐 App Secret": r"(?i)(app_?secret|client_?secret|sign_?key)\":\s*\"([a-zA-Z0-9]{10,})\"",
    "🔒 License Key": r"(?i)key\":\s*\"([a-zA-Z0-9]{16,})\"",
}

# --- TARGET EXTENSIONS ---
# We only care about config files, not images or code
TARGET_EXTS = [".json", ".xml", ".properties", ".txt", ".yaml"]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Starting Asset Stripper on {apk_path}...")
    try:
        found_secrets = []
        
        # Open APK as a ZIP file
        with zipfile.ZipFile(apk_path, 'r') as z:
            # List all files inside
            file_list = z.namelist()
            
            # Filter for assets/ and res/raw/
            config_files = [f for f in file_list if any(x in f for x in ["assets/", "res/raw/"]) and any(f.endswith(ext) for ext in TARGET_EXTS)]
            
            print(f"[*] Scanning {len(config_files)} configuration files...")

            for filename in config_files:
                try:
                    # Read the file content
                    content = z.read(filename).decode('utf-8', errors='ignore')
                    
                    # 1. Check for Specific Patterns
                    for name, pattern in PATTERNS.items():
                        matches = re.findall(pattern, content)
                        for match in matches:
                            # match is usually a tuple (key, value), we want the value
                            val = match[1] if isinstance(match, tuple) else match
                            found_secrets.append(f"📂 {filename}\n  {name}: `{val}`")
                            
                    # 2. Heuristic: Look for "tuya" config files specifically
                    if "tuya" in filename and "json" in filename:
                         found_secrets.append(f"📄 **Found Tuya Config:** {filename}")
                         # Dump the first 200 chars to see what's inside
                         found_secrets.append(f"```{content[:200]}...```")

                except Exception as e:
                    pass

        # REPORT
        if found_secrets:
            report = f"🗝️ **Asset Stripper Report**\n\n"
            report += "\n\n".join(found_secrets[:15]) # Limit to top 15 findings
            print(report)
            send_telegram_alert(report)
        else:
            msg = "[-] No keys found in asset configuration files."
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
