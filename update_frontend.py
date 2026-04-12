"""
update_frontend.py
------------------
1. Gets the live ngrok URL
2. Writes api.txt locally
3. Pushes api.txt + server.json to GitHub
4. Updates Cloudflare Worker NGROK_URL env var automatically
   so the worker always points to the current ngrok tunnel

Set in backend/.env:
  CF_ACCOUNT_ID=your_cloudflare_account_id
  CF_WORKER_NAME=mypocketdrive
  CF_API_TOKEN=your_cloudflare_api_token   (needs Workers:Edit permission)
  WORKER_URL=https://mypocketdrive.YOUR-SUBDOMAIN.workers.dev
"""

import sys, time, json, base64, os, urllib.request, urllib.error, datetime
from pathlib import Path

SCRIPT_DIR    = Path(__file__).parent.resolve()
ENV_PATH      = SCRIPT_DIR / "backend" / ".env"
LOCAL_API_TXT = SCRIPT_DIR / "api.txt"


def load_env(path):
    if not path.exists():
        print(f"[ERROR] .env not found at {path}")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())

load_env(ENV_PATH)

GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO    = os.getenv("GITHUB_REPO", "")
GITHUB_BRANCH  = os.getenv("GITHUB_BRANCH", "main")
FRONTEND_URL   = os.getenv("FRONTEND_URL", "").rstrip("/")
CF_ACCOUNT_ID  = os.getenv("CF_ACCOUNT_ID", "")
CF_WORKER_NAME = os.getenv("CF_WORKER_NAME", "mypocketdrive")
CF_API_TOKEN   = os.getenv("CF_API_TOKEN", "")
WORKER_URL     = os.getenv("WORKER_URL", "").rstrip("/")


# ── ngrok ─────────────────────────────────────────────────────────────────────

def fetch_ngrok_url(retries=12, delay=2):
    for attempt in range(retries):
        try:
            req = urllib.request.Request("http://127.0.0.1:4040/api/tunnels")
            with urllib.request.urlopen(req, timeout=3) as res:
                data = json.loads(res.read())
                for t in data.get("tunnels", []):
                    url = t.get("public_url", "")
                    if url.startswith("https://"):
                        return url.rstrip("/")
        except Exception:
            pass
        print(f"  Waiting for ngrok... ({attempt+1}/{retries})")
        time.sleep(delay)
    raise RuntimeError("Could not get ngrok URL — is ngrok running?")


# ── GitHub ─────────────────────────────────────────────────────────────────────

def gh_get(filepath):
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{filepath}?ref={GITHUB_BRANCH}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "TGDrive-Updater",
    })
    try:
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read())
        return base64.b64decode(data["content"]).decode("utf-8"), data["sha"]
    except Exception:
        return None, None


def gh_put(filepath, content_str, sha, msg):
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{filepath}"
    body = {
        "message": msg,
        "content": base64.b64encode(content_str.encode("utf-8")).decode("utf-8"),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        body["sha"] = sha
    payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="PUT", headers={
        "Authorization": f"token {GITHUB_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "TGDrive-Updater",
    })
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read())


# ── Cloudflare Worker ──────────────────────────────────────────────────────────

def update_cloudflare_worker(ngrok_url: str) -> bool:
    """Update the NGROK_URL environment variable in the Cloudflare Worker."""
    if not CF_ACCOUNT_ID or not CF_API_TOKEN:
        print("  [SKIP] CF_ACCOUNT_ID or CF_API_TOKEN not set — skipping Cloudflare update.")
        print("         Set these in backend/.env to enable auto-update.")
        return False

    url = (f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}"
           f"/workers/scripts/{CF_WORKER_NAME}/bindings")

    # Cloudflare Workers env vars are set via the bindings API or wrangler.
    # For plain env vars we use the script settings API:
    settings_url = (f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}"
                    f"/workers/scripts/{CF_WORKER_NAME}/script-settings")

    payload = json.dumps({
        "bindings": [
            {
                "type": "plain_text",
                "name": "NGROK_URL",
                "text": ngrok_url,
            }
        ]
    }).encode("utf-8")

    req = urllib.request.Request(
        settings_url,
        data=payload,
        method="PATCH",
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type": "application/json",
        }
    )
    try:
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read())
        if data.get("success"):
            return True
        print(f"  [WARN] Cloudflare API returned: {data.get('errors', data)}")
        return False
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  [WARN] Cloudflare update failed ({e.code}): {body[:200]}")
        return False
    except Exception as e:
        print(f"  [WARN] Cloudflare update error: {e}")
        return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not GITHUB_TOKEN:
        print("\n[ERROR] GITHUB_TOKEN not set in backend/.env")
        sys.exit(1)
    if not GITHUB_REPO:
        print("\n[ERROR] GITHUB_REPO not set in backend/.env")
        sys.exit(1)

    print("\n  Fetching ngrok URL...")
    try:
        ngrok_url = fetch_ngrok_url()
    except RuntimeError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    print(f"  OK - ngrok URL: {ngrok_url}")

    # The public URL for share links — use Worker URL if configured, else ngrok
    # ALWAYS use Worker URL for api.txt if configured
    # This ensures the agent never gets the raw ngrok URL (which shows interstitial)
    if WORKER_URL:
        public_url = WORKER_URL
        print(f"  Using Worker URL: {public_url}")
    else:
        public_url = ngrok_url
        print(f"  [WARN] WORKER_URL not set in .env — using raw ngrok URL")
        print(f"  [WARN] Add WORKER_URL=https://spring-bar-6474.noreplymypocketdrive.workers.dev")
        print(f"  [WARN] to backend/.env to avoid ngrok interstitial issues")

    # Write api.txt — use Worker URL so frontend always uses clean URL
    LOCAL_API_TXT.write_text(public_url, encoding="utf-8")
    print("  OK - Local api.txt written.")

    # Push api.txt to GitHub
    print("  Pushing api.txt to GitHub...")
    try:
        _, sha = gh_get("api.txt")
        gh_put("api.txt", public_url, sha, f"chore: update API URL to {public_url}")
        print("  OK - api.txt pushed to GitHub.")
    except Exception as e:
        print(f"\n[ERROR] Could not push api.txt: {e}")
        sys.exit(1)

    # Push server.json
    print("  Pushing server.json to GitHub...")
    try:
        server_json = json.dumps({
            "url":     public_url,
            "updated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "version": "6",
        }, indent=2)
        _, sha_j = gh_get("server.json")
        gh_put("server.json", server_json, sha_j, f"chore: update server URL to {public_url}")
        print("  OK - server.json pushed to GitHub.")
    except Exception as e:
        print(f"  [WARN] Could not push server.json: {e}")

    # Update Cloudflare Worker with latest ngrok URL
    if CF_ACCOUNT_ID and CF_API_TOKEN:
        print("  Updating Cloudflare Worker NGROK_URL...")
        ok = update_cloudflare_worker(ngrok_url)
        if ok:
            print(f"  OK - Worker now points to: {ngrok_url}")
        else:
            print(f"  [WARN] Worker update failed — update NGROK_URL manually in Cloudflare dashboard.")
    else:
        print("  [INFO] Cloudflare Worker not configured — skipping auto-update.")
        print("         After ngrok starts, update NGROK_URL in Cloudflare dashboard manually.")

    print(f"""
  =========================================
  MyPocketDrive is LIVE

  ngrok backend : {ngrok_url}
  Public URL    : {public_url}
  Frontend      : {FRONTEND_URL or 'https://mypocketdrive.online'}

  Share links will use: {public_url}/share/...
  =========================================
""")


if __name__ == "__main__":
    main()
