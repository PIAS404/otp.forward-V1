#!/usr/bin/env python3

import os
import time
import json
import re
import hashlib
import requests
from websocket import WebSocketApp
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# -------- ENV --------
IVAS_EMAIL = os.getenv("IVAS_EMAIL")
IVAS_PASSWORD = os.getenv("IVAS_PASSWORD")
IVAS_LOGIN_URL = os.getenv("IVAS_LOGIN_URL")
IVAS_BASE_URL = os.getenv("IVAS_BASE_URL")
WS_URL = os.getenv("WS_URL")

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

if not (IVAS_EMAIL and IVAS_PASSWORD and WS_URL and BOT_TOKEN and CHAT_ID):
    raise SystemExit("Missing required env vars. Set required fields in .env")

# -------- Helpers --------
OTP_RE = re.compile(r"\b(\d{4,8})\b")
seen = set()

def send_telegram(msg):
    try:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": msg}
        )
    except Exception as e:
        print("Telegram send error:", e)

def login_to_ivas():
    s = requests.Session()
    try:
        r = s.get(IVAS_LOGIN_URL, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")

        # Build payload
        payload = {}
        if form:
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                t = inp.get("type", "").lower()
                if t == "password":
                    payload[name] = IVAS_PASSWORD
                elif t == "email" or "user" in name.lower():
                    payload[name] = IVAS_EMAIL
                else:
                    payload[name] = inp.get("value", "")
        else:
            payload = {"email": IVAS_EMAIL, "password": IVAS_PASSWORD}

        action = form.get("action") if form else IVAS_LOGIN_URL
        if action.startswith("/"):
            action = IVAS_BASE_URL + action

        print("[*] Logging in to IVAS...")
        s.post(action, data=payload, timeout=10)

        return s
    except Exception as e:
        print("Login error:", e)
        return None

def extract_socketio_json(msg):
    try:
        if msg.startswith("42"):
            return json.loads(msg[2:])
        idx = msg.find("[")
        if idx != -1:
            return json.loads(msg[idx:])
    except:
        pass
    return None

def process_otp(obj):
    if isinstance(obj, list):
        text = json.dumps(obj[1], ensure_ascii=False) if len(obj) > 1 else json.dumps(obj)
    elif isinstance(obj, dict):
        text = json.dumps(obj, ensure_ascii=False)
    else:
        text = str(obj)

    h = hashlib.sha256(text.encode()).hexdigest()
    if h in seen:
        return
    seen.add(h)

    print("[INCOMING]:", text[:200])

    digits = OTP_RE.findall(text)
    if digits or any(k in text.lower() for k in ["code", "otp", "pin"]):
        send_telegram(f"📩 OTP Detected\n{text}")

def on_message(ws, message):
    parsed = extract_socketio_json(message)
    if parsed:
        process_otp(parsed)
    else:
        try:
            j = json.loads(message)
            process_otp(j)
        except:
            process_otp(message)

def on_open(ws):
    print("[*] WebSocket Connected")

def on_error(ws, error):
    print("[!] WS Error:", error)

def on_close(ws, code, reason):
    print("[!] WS Closed:", code, reason)

def start_bot():
    session = login_to_ivas()
    if not session:
        print("Login failed!")
        return

    cookie = "; ".join([f"{c.name}={c.value}" for c in session.cookies])

    headers = {
        "Cookie": cookie,
        "Origin": IVAS_BASE_URL,
        "Referer": IVAS_BASE_URL + "/portal/live/test_sms"
    }

    while True:
        try:
            ws = WebSocketApp(
                WS_URL,
                header=[f"{k}: {v}" for k, v in headers.items()],
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close
            )
            ws.run_forever(ping_interval=20, ping_timeout=10)
        except Exception as e:
            print("Reconnect error:", e)
            time.sleep(5)

if __name__ == "__main__":
    print("Starting IVAS → Telegram OTP Forwarder…")
    start_bot()
