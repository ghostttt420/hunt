import os
import re
import requests
import zipfile
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- CAMERA PATTERNS ---
# We are looking for connection strings and default creds
PATTERNS = {
    "🎥 RTSP Stream": r"rtsp://[\w./:\-@]+",
    "🎥 RTMP Stream": r"rtmp://[\w./:\-@]+",
    "🎥 HTTP Stream": r"http://[\w./:\-]+(?:\.m3u8|\.flv|\.mp4|/live|/stream)",
    "📡 ONVIF Discovery": r"onvif://[\w./:\-]+",
    "🔑 Admin User": r"(?i)(admin|root|user|guest)",
    "🔑 Hardcoded Pass": r"(?i)(password|pwd|passwd)\s*[:=]\s*[\"']?([a-zA-Z0-9@!#]{3,})[\"']?",
    "🔧 Default IP": r"192\.168\.\d{1,3}\.\d{1,3}",
    "☁️ Cloud P2P": r"(?i)(p2p|tutk|kalay|avs)\.[\w.]+"
}

def send_telegram_alert(message):
    if not TELEGRAM_BOT_TOKEN: return
    if len(message) > 4000: message = message[:4000] + "\n...[TRUNCATED]"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "disable_web_page_preview": True}
    try: requests.post(url, data=data)
    except: pass

def analyze_apk(apk_path):
    print(f"[*] Starting 'Voyeur' Scan on {apk_path}...")
    report = f"📹 **Camera Hunter Report: {apk_path}**\n\n"
    
    found_items = set()

    try:
        # 1. SCAN NATIVE LIBRARIES (.so files)
        # This is where 90% of camera secrets live
        print("[*] Unzipping and scanning native libs...")
        with zipfile.ZipFile(apk_path, 'r') as z:
            for filename in z.namelist():
                if filename.endswith(".so"):
                    content = z.read(filename)
                    # Simple strings extraction from binary
                    try:
                        # Decode with ignore to get ASCII strings
                        text = content.decode('latin-1') 
                        # Scan for patterns
                        for name, pattern in PATTERNS.items():
                            matches = re.findall(pattern, text)
                            for m in matches:
                                if isinstance(m, tuple): m = m[0] # Handle groups
                                if len(m) > 4 and len(m) < 100: # Filter noise
                                    found_items.add(f"{name} (in {filename}): `{m}`")
                    except: pass

        # 2. SCAN JAVA CODE (Dex)
        print("[*] Decompiling Java code...")
        app, dex_list, dx = AnalyzeAPK(apk_path)
        
        all_strings = set()
        for dex in dex_list:
            for s in dex.get_strings():
                all_strings.add(str(s))
        
        print(f"[*] Scanning {len(all_strings)} strings...")
        for s in all_strings:
            for name, pattern in PATTERNS.items():
                matches = re.findall(pattern, s)
                for m in matches:
                    if isinstance(m, tuple): m = m[0]
                    if len(m) > 4 and len(m) < 100:
                        found_items.add(f"{name}: `{m}`")

        # 3. REPORT
        if found_items:
            # Sort and prioritize URLs
            sorted_items = sorted(list(found_items))
            # Move RTSP to top
            rtsp = [i for i in sorted_items if "rtsp" in i]
            others = [i for i in sorted_items if "rtsp" not in i]
            
            report += "**🔥 Live Streams (Gold):**\n" + ("\n".join(rtsp) if rtsp else "None found") + "\n\n"
            report += "**🕵️ Other Findings:**\n" + "\n".join(others[:30])
        else:
            report += "[-] No obvious camera secrets found."

        print(report)
        send_telegram_alert(report)

    except Exception as e:
        err = f"⚠️ Error: {e}"
        print(err)
        send_telegram_alert(err)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
