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

# --- TARGET ---
# We stick to the US server because it accepted our Key
BASE_URL = "https://a1.tuyaus.com/api.json"

# --- FUZZ LIST ---
# We know the command exists, we just need the version.
# We also add a few other "Tuya" commands that might leak info.
COMMANDS = [
    "tuya.m.device.upgrade.detail",
    "tuya.m.device.ota.info",
    "tuya.m.my.group.device.list", # Might leak device details
]

VERSIONS = ["1.0", "1.1", "1.2", "2.0", "3.0", "4.0", "4.1", "4.2", "4.3", "4.4", "4.5"]

def get_sign(params, secret):
    sorted_keys = sorted(params.keys())
    to_sign = "||".join(f"{k}={params[k]}" for k in sorted_keys)
    to_sign += "||" + secret
    return hashlib.md5(to_sign.encode('utf-8')).hexdigest()

def run():
    print(f"[*] Starting Version Brute-Force on US Server...")
    
    found_something = False

    for cmd in COMMANDS:
        print(f"\n🔨 Fuzzing Command: {cmd}")
        for v in VERSIONS:
            params = {
                "a": cmd,
                "devId": DEVICE_ID,
                "time": str(int(time.time())),
                "client_id": CLIENT_ID,
                "v": v,
                "os": "Android",
                "nonce": str(uuid.uuid4())
            }
            
            params["sign"] = get_sign(params, APP_SECRET)
            
            try:
                r = requests.post(BASE_URL, data=params)
                data = r.json()
                
                # Check if it worked
                if data.get("success"):
                    print(f"   ✅ JACKPOT! Version {v} worked!")
                    print(f"   Payload: {data}")
                    
                    # Check for URL
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
                        sys.exit(0)
                    
                    found_something = True
                
                elif data.get("errorCode") == "API_OR_API_VERSION_WRONG":
                    # This means we are close, but wrong version
                    print(f"   . v{v} (Wrong Version)")
                else:
                    # Some other error (Permissions etc)
                    print(f"   ⚠️ v{v} Error: {data.get('errorCode')}")

            except Exception as e:
                print(f"   Connection Error: {e}")

    if found_something:
        print("\n[+] We found valid commands, but no firmware URL (Device is likely updated).")
        sys.exit(0)
    else:
        print("\n[-] Brute force failed.")
        sys.exit(1)

if __name__ == "__main__":
    run()
