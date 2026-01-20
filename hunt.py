import os
import zipfile
import json

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- TARGETS ---
# We saw these files in your logs. They likely contain the init config.
TARGET_FILES = [
    "assets/thing_plugin_config.json",
    "assets/ty_plugin_config.json", 
    "assets/x_platform_config.json",
    "assets/configList.json",
    "assets/thing_pbt_group_config.json",
    "assets/ty_pbt_group_config.json"
]

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    # Chunk long messages
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Dumping Configs from {apk_path}...")
    try:
        report = f"📂 **Config Dump Report**\n"
        
        with zipfile.ZipFile(apk_path, 'r') as z:
            # Check which targets actually exist in this APK
            all_files = z.namelist()
            
            for target in TARGET_FILES:
                if target in all_files:
                    print(f"[*] Reading {target}...")
                    try:
                        # Read the file
                        content_bytes = z.read(target)
                        content_str = content_bytes.decode('utf-8', errors='ignore')
                        
                        # Formatting: If it's JSON, try to pretty print it
                        try:
                            json_obj = json.loads(content_str)
                            # Minify it slightly to fit more in the message
                            formatted_content = json.dumps(json_obj, indent=2)
                        except:
                            formatted_content = content_str
                        
                        report += f"\n\n📄 **File: {target}**\n"
                        report += f"```json\n{formatted_content[:1000]}\n```" # First 1000 chars
                        
                    except Exception as e:
                        report += f"\n❌ Error reading {target}: {e}"
        
        print(report)
        send_telegram_alert(report)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    import requests # Imported here to be safe
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
