import hashlib
import time
import requests
import uuid
import os
import sys

# --- CONFIGURATION ---
CLIENT_ID = "fmwgqwn7kqfcp793mftn"      
APP_SECRET = "4dv444aexjrkemfgdhecsdkyxe5hcp7h" 
DEVICE_ID = "1090522143161722"

# --- THE CORRECT COMMANDS ---
# Based on your "Global Grep" report
TARGETS = [
    # 1. The most likely candidate (found in your screenshot)
    ("thing.m.device.upgrade.info", "1.0"),
    ("thing.m.device.upgrade.info", "4.0"),
    
    # 2. Backups (also found in your screenshot)
    ("thing.m.device.upgrade.detail", "1.0"), 
    ("thing.m.device.product.upgrade.confirm", "1.0") 
]

def get_sign(params, secret):
    sorted_keys = sorted(params.keys())
    to_sign = "||".join(f"{k}={params[k]}" for k in sorted_keys)
    to_sign += "||" + secret
    return hashlib.md5(to_sign.encode('utf-8')).hexdigest()

def run():
    print(f"[*] Authenticating as Device: {DEVICE_ID}")

    for api, version in TARGETS:
        print(f"\n👉 Testing: {api} (v{version})...")
        
        params = {
            "a": api,
            "devId": DEVICE_ID,
            "time": str(int(time.time())),
            "client_id": CLIENT_ID,
            "v": version,
            "os": "Android",
            "nonce": str(uuid.uuid4())
        }
        
        params["sign"] = get_sign(params, APP_SECRET)
        
        try:
            r = requests.post("https://a1.tuyaus.com/api.json", data=params)
            data = r.json()
            
            if data.get("success"):
                print("✅ SUCCESS!")
                print(data)
                
                # Check for URL in the result
                result = data.get("result")
                url = None
                
                if isinstance(result, dict):
                    url = result.get("url") or result.get("otaUrl")
                elif isinstance(result, list) and result:
                    url = result[0].get("url") or result[0].get("otaUrl")
                    
                if url:
                    print(f"\n🚨 FIRMWARE FOUND: {url}")
                    if "GITHUB_OUTPUT" in os.environ:
                        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                            f.write(f"firmware_url={url}\n")
                    sys.exit(0) # Stop, we won
                else:
                    print("[-] Command worked, but no firmware link (Device is likely up to date).")
                    sys.exit(0) # Stop, we proved access
            else:
                print(f"❌ Failed: {data.get('errorCode')}")

        except Exception as e:
            print(f"⚠️ Network Error: {e}")

    print("\n[-] No link found, but we tested all known commands.")
    sys.exit(1)

if __name__ == "__main__":
    run()
