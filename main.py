# IVAS SMS WebSocket -> Telegram Forwarder
# GitHub-safe version (no hardcoded secrets)
# ------------------------------------------------
# Create a .env file with:
# BOT_TOKEN=your_bot_token
# CHAT_ID=your_chat_id
# WS_URL=wss_url_from_network_tab
# ------------------------------------------------

import os
import re
import json
import time
import hashlib
import requests
from websocket import WebSocketApp
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
WS_URL = os.getenv("WS_URL")  # wss://ivasms.com:2087/socket.io/?UserName=...&Email=...&EIO=4&transport=websocket

if not BOT_TOKEN or not CHAT_ID or not WS_URL:
    raise Exception("Missing environment variables. Please set BOT_TOKEN, CHAT_ID, and WS_URL in .env file.")

# Storage for duplicate prevention
seen = set()

# OTP Regex: detects 4-8 digit OTP codes
OTP_RE = re.compile(r"\b(\d{4,8})\b")

def send_telegram(text):
    """Send formatted text to Telegram chat"""
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": text}
        )
        if resp.status_code != 200:
            print("Telegram error:", resp.text)
    except Exception as e:
        print("Telegram exception:", e)

def extract_json_from_socketio(msg: str):
    """
    Extract JSON from socket.io frames.
    Common format: 42["event", {...}]
    """
    try:
        if msg.startswith("42"):
            return json.loads(msg[2:])
        idx = msg.find('[')
        if idx != -1:
            return json.loads(msg[idx:])
    except Exception:
        pass
    return None

def process_payload(obj):
    """
    Extract meaningful text from socket.io payload.
    Detect OTP codes and forward to Telegram.
    """
    try:
        if isinstance(obj, list):
            text = json.dumps(obj[1], ensure_ascii=False) if len(obj) > 1 else json.dumps(obj)
        elif isinstance(obj, dict):
            text = json.dumps(obj, ensure_ascii=False)
        else:
            text = str(obj)

        uid = hashlib.sha256(text.encode()).hexdigest()
        if uid in seen:
            return
        seen.add(uid)

        print("INCOMING:", text[:300])

        digits = OTP_RE.findall(text)
        keywords = any(k in text.lower() for k in ["code", "otp", "pin", "password"])

        if digits or keywords:
            codes = ", ".join(dict.fromkeys(digits)) if digits else "N/A"
            send_telegram(f"📩 NEW OTP DETECTED\nCodes: {codes}\n\n{text}")
    except Exception as e:
        print("Payload error:", e)

def on_message(ws, message):
    try:
        parsed = extract_json_from_socketio(message)
        if parsed is not None:
            process_payload(parsed)
        else:
            try:
                j = json.loads(message)
                process_payload(j)
            except:
                process_payload(message)
    except Exception as e:
        print("on_message error:", e)

def on_open(ws):
    print("Connected to WebSocket:", WS_URL)

def on_error(ws, error):
    print("WebSocket error:", error)

def on_close(ws, code, reason):
    print("WebSocket closed:", code, reason)

def run_forever():
    while True:
        try:
            ws = WebSocketApp(
                WS_URL,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close,
            )
            ws.run_forever(ping_interval=20, ping_timeout=10)
        except Exception as e:
            print("Reconnection error:", e)
            time.sleep(5)

if __name__ == "__main__":
    print("Starting IVAS → Telegram Forwarder...")
    run_forever()
