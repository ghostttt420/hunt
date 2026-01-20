import os
import sys
import re
import requests
from androguard.misc import AnalyzeAPK

# --- CONFIGURATION ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# --- TARGETS ---
# We only want to look inside these specific files
TARGET_CLASSES = ["ApiConstant", "AgentTokenRequestParams"]

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
        
        report_lines = []
        report_lines.append(f"🔬 **Inspector Report: {package}**")

        for dex in dex_list:
            for current_class in dex.get_classes():
                class_name = current_class.get_name() # Returns Lcom/package/Name;
                
                # Check if this class matches our targets
                if any(t in class_name for t in TARGET_CLASSES):
                    clean_name = class_name.split('/')[-1].replace(';', '').replace('L', '')
                    report_lines.append(f"\n📂 **File: {clean_name}**")
                    
                    # 1. READ VARIABLES (Fields)
                    # This tells us the JSON keys (e.g., "username", "password")
                    fields = current_class.get_fields()
                    if fields:
                        report_lines.append("  -- Variables --")
                        for field in fields:
                            report_lines.append(f"  • {field.get_name()}")

                    # 2. READ CONSTANT VALUES (Static Initializers)
                    # This tells us the Hardcoded URLs or Keys
                    # We look for the <clinit> method (Static Constructor)
                    for method in current_class.get_methods():
                        if method.get_name() == "<clinit>":
                            # This gets the code inside the static block
                            code = method.get_code()
                            if code:
                                # We define a set to catch unique strings
                                const_strings = set() 
                                # Bytecode hack: Look for string constants used in this method
                                for instr in code.get_bc().get_instructions():
                                    output = instr.get_output()
                                    # If the instruction loads a string, grab it
                                    if '"' in output:
                                        # Clean up the string syntax
                                        clean_str = output.split('"')[1]
                                        if len(clean_str) > 2:
                                            const_strings.add(clean_str)
                                
                                if const_strings:
                                    report_lines.append("  -- Hardcoded Values --")
                                    for s in const_strings:
                                        report_lines.append(f"  🔑 {s}")

        # Send Report
        final_report = "\n".join(report_lines)
        print(final_report)
        send_telegram_alert(final_report[:4000]) # Telegram limit

    except Exception as e:
        err_msg = f"⚠️ Error: {e}"
        print(err_msg)
        send_telegram_alert(err_msg)

if __name__ == "__main__":
    files = [f for f in os.listdir('.') if f.endswith('.apk')]
    if files: analyze_apk(files[0])
    else: print("No APK found.")
