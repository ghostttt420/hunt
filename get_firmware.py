import hashlib
import time
import requests
import uuid
import os
import sys

# --- TARGET CONFIGURATION ---
# Extracted from your AndroidManifest.xml
CLIENT_ID = "fmwgqwn7kqfcp793mftn"      
APP_SECRET = "4dv444aexjrkemfgdhecsdkyxe5hcp7h" 
# Extracted from your initial scan
DEVICE_ID = "1090522143161722"

def get_sign(params, secret):
    """Generates the MD5 signature required by Tuya IoT API."""
    # 1. Sort all parameters alphabetically
    sorted_keys = sorted(params.keys())
    # 2. Join them as key=value||key=value
    to_sign = "||".join(f"{k}={params[k]}" for k in sorted_keys)
    # 3. Append the secret
    to_sign += "||" + secret
    # 4. MD5 Hash
    return hashlib.md5(to_sign.encode('utf-8')).hexdigest()

def run():
    print(f"[*] Authenticating as Device: {DEVICE_ID}")
    
    # Prepare standard parameters
    params = {
        "a": "tuya.m.device.upgrade.detail",
        "devId": DEVICE_ID,
        "time": str(int(time.time())),
        "client_id": CLIENT_ID,
        "v": "1.0",
        "os": "Android",
        "nonce": str(uuid.uuid4())
    }
    
    # Sign the request
    params["sign"] = get_sign(params, APP_SECRET)
    
    # Send to Tuya US Server (Common for OhmPlug)
    try:
        r = requests.post("https://a1.tuyaus.com/api.json", data=params)
        data = r.json()
        
        print(f"[*] API Response: {data}")
        
        if "result" in data and data["result"]:
            url = data["result"].get("url")
            if url:
                print(f"🚨 FIRMWARE FOUND: {url}")
                # Write to GitHub Output so the next step can use it
                if "GITHUB_OUTPUT" in os.environ:
                    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                        f.write(f"firmware_url={url}\n")
            else:
                print("[-] Device is up to date (No download link provided).")
                sys.exit(1) 
        else:
            print("[-] API Error or No Result.")
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run()
