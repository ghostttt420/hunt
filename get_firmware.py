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

# --- THE FUZZ LIST ---
# We will try these commands in order. 
# One of them contains the download link.
TARGETS = [
    # Modern Standard (Most likely)
    ("tuya.m.device.upgrade.detail", "4.3"),
    ("tuya.m.device.upgrade.detail", "4.4"),
    ("tuya.m.device.upgrade.detail", "4.0"),
    
    # Legacy / Alternative
    ("tuya.m.device.ota.info", "1.0"),
    ("tuya.m.device.upgrade.status", "1.0"),
    ("tuya.m.ota.firmware.list", "1.0"),
    
    # "Thing" Rebrand (Newest)
    ("thing.m.device.upgrade.detail", "1.0"),
    ("thing.m.device.upgrade.detail", "4.0"),
]

def get_sign(params, secret):
    sorted_keys = sorted(params.keys())
    to_sign = "||".join(f"{k}={params[k]}" for k in sorted_keys)
    to_sign += "||" + secret
    return hashlib.md5(to_sign.encode('utf-8')).hexdigest()

def run():
    print(f"[*] Authenticating as Device: {DEVICE_ID}")
    print(f"[*] Keys: {CLIENT_ID[:5]}... / {APP_SECRET[:5]}...")

    success = False

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
        
        # Sign and Send
        params["sign"] = get_sign(params, APP_SECRET)
        
        try:
            r = requests.post("https://a1.tuyaus.com/api.json", data=params)
            data = r.json()
            
            # Check for generic success
            if data.get("success"):
                print("✅ SUCCESS!")
                print(data)
                
                # Check for Payload
                result = data.get("result")
                if result:
                    # Sometimes result is a list, sometimes a dict
                    if isinstance(result, list) and len(result) > 0:
                        result = result[0]
                    
                    # Look for the URL
                    url = result.get("url") or result.get("otaUrl") or result.get("typeUrl")
                    
                    if url:
                        print(f"\n🚨 FIRMWARE FOUND: {url}")
                        if "GITHUB_OUTPUT" in os.environ:
                            with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                                f.write(f"firmware_url={url}\n")
                        success = True
                        break
                    else:
                        print("[-] Command worked, but no firmware link in response (Device might be up to date).")
                else:
                    print("[-] Command worked, but result was empty.")
            else:
                print(f"❌ Failed: {data.get('errorCode')} - {data.get('errorMsg')}")

        except Exception as e:
            print(f"⚠️ Network Error: {e}")

    if not success:
        print("\n[-] Exhausted all attempts. No firmware link found.")
        sys.exit(1)

if __name__ == "__main__":
    run()
