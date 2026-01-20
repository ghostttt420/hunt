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

# --- GLOBAL REGIONS ---
# We will hop through these until one accepts our ID
REGIONS = [
    ("US (United States)", "https://a1.tuyaus.com/api.json"),
    ("EU (Europe)", "https://a1.tuyaeu.com/api.json"),
    ("CN (China)", "https://a1.tuyacn.com/api.json"),
    ("IN (India)", "https://a1.tuyain.com/api.json")
]

# --- COMMAND LIST ---
# Mixing "Thing" (New) and "Tuya" (Old) just to be safe
TARGET_CMDS = [
    ("thing.m.device.upgrade.info", "1.0"),  # The one we found in strings
    ("tuya.m.device.upgrade.detail", "4.3"), # The standard backup
]

def get_sign(params, secret):
    sorted_keys = sorted(params.keys())
    to_sign = "||".join(f"{k}={params[k]}" for k in sorted_keys)
    to_sign += "||" + secret
    return hashlib.md5(to_sign.encode('utf-8')).hexdigest()

def run():
    print(f"[*] Starting Global Region Hop for Device: {DEVICE_ID}")

    for region_name, base_url in REGIONS:
        print(f"\n🌍 Jumping to Region: {region_name}")
        
        for api, version in TARGET_CMDS:
            print(f"   👉 Testing: {api} (v{version})...")
            
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
                r = requests.post(base_url, data=params, timeout=5)
                data = r.json()
                
                # Check for Authentication Success
                # ILLEGAL_CLIENT_ID means wrong region. 
                # Anything else (even an empty result) means RIGHT region.
                error_code = data.get("errorCode", "")
                
                if error_code == "ILLEGAL_CLIENT_ID":
                    print("   ❌ Wrong Region (Key not found here)")
                    continue # Try next command, then next region
                
                # If we get here, the Key IS valid in this region
                print(f"   ✅ REGION MATCH! Server accepted the Key.")
                print(f"   Response: {data}")
                
                if data.get("success"):
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
                    else:
                        print("   [-] Authorized, but no firmware link in response.")
                        # We found the region, but maybe not the right command version
                        # We don't exit here, we let it finish the loop in this region
                else:
                    print(f"   ⚠️ Key Accepted, but API Failed: {error_code}")
                    
            except Exception as e:
                print(f"   ⚠️ Connection Error: {e}")

    print("\n[-] Global scan complete.")
    sys.exit(1)

if __name__ == "__main__":
    run()
