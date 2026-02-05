from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re

app = FastAPI()

# ================= CONFIG =================
API_KEY = "my_secret_key_123"

# ================= MEMORY =================
sessions = {}

# ================= MODELS =================
class Message(BaseModel):
    sender: str
    text: str

class RequestBody(BaseModel):
    sessionId: str
    message: Message

# ================= SCAM DETECTION =================
def is_scam(message: str) -> bool:
    keywords = [
        "account", "blocked", "urgent", "verify",
        "bank", "upi", "click", "otp", "send money"
    ]
    msg = message.lower()
    return any(word in msg for word in keywords)

# ================= SMART HONEYPOT REPLY =================
def agent_reply(message: str) -> str:
    msg = message.lower()

    if "upi" in msg or "send money" in msg or "transfer" in msg:
        return "My bank app is not opening, which account should I send it to?"
    elif "link" in msg or "click" in msg:
        return "This link is not opening, can you send it again?"
    elif "account" in msg or "blocked" in msg:
        return "Why will my account be blocked? Please explain clearly."
    else:
        return "I don’t understand, can you explain this properly?"

# ================= INTELLIGENCE EXTRACTION =================
def extract_intelligence(text: str):
    return {
        "upi_ids": re.findall(r'\b[\w.-]+@upi\b', text),
        "phishing_links": re.findall(r'https?://\S+', text)
    }

# ================= API ENDPOINT =================
@app.post("/analyze")
def analyze(
    data: RequestBody,
    x_api_key: str = Header(None)
):
    # 🔐 API KEY CHECK
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = data.sessionId
    message_text = data.message.text
    sender = data.message.sender

    # Create session if new
    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "intelligence": {
                "upi_ids": [],
                "phishing_links": []
            }
        }

    # Save incoming message
    sessions[session_id]["history"].append({
        "sender": sender,
        "text": message_text
    })

    scam_detected = is_scam(message_text)
    reply = None

    if scam_detected:
        reply = agent_reply(message_text)

        sessions[session_id]["history"].append({
            "sender": "user",
            "text": reply
        })

    # Extract intelligence from scammer message
    extracted = extract_intelligence(message_text)
    sessions[session_id]["intelligence"]["upi_ids"].extend(extracted["upi_ids"])
    sessions[session_id]["intelligence"]["phishing_links"].extend(extracted["phishing_links"])

    return {
        "status": "success",
        "scam_detected": scam_detected,
        "reply": reply,
        "session_memory": sessions[session_id]
    }
