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
        "bank", "upi", "click", "otp",
        "locked", "fraud", "security", "breach"
    ]
    msg = message.lower()
    return any(word in msg for word in keywords)

# ================= SMART HONEYPOT REPLY =================
def agent_reply(message: str) -> str:
    msg = message.lower()

    # OTP based scams
    if "otp" in msg:
        return (
            "I received multiple OTP messages and I am confused. "
            "Which exact OTP should I share and why?"
        )

    # Account blocked / locked threats
    if "blocked" in msg or "locked" in msg:
        return (
            "This is very stressful. Can you hold the block for a few minutes "
            "while I contact my bank manager?"
        )

    # Account number requests
    if "account number" in msg:
        return (
            "This account number does not look familiar to me. "
            "Can you tell me the bank branch or account type linked to it?"
        )

    # Security breach / fraud
    if "security" in msg or "fraud" in msg or "breach" in msg:
        return (
            "Before I proceed, can you please confirm your employee ID "
            "or department? I need this for my safety."
        )

    # Urgency pressure
    if "urgent" in msg or "immediately" in msg or "minutes" in msg:
        return (
            "I have not tried logging in today. "
            "Which device or location caused this issue?"
        )

    # Default confusion reply
    return (
        "I don’t understand this properly. "
        "Can you explain why this is happening?"
    )

# ================= INTELLIGENCE EXTRACTION =================
def extract_intelligence(text: str):
    return {
        "upi_ids": re.findall(r'\b[\w.-]+@upi\b', text),
        "phishing_links": re.findall(r'https?://\S+', text),
        "phone_numbers": re.findall(r'\+91-\d{10}', text),
        "account_numbers": re.findall(r'\b\d{9,18}\b', text)
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
                "phishing_links": [],
                "phone_numbers": [],
                "account_numbers": []
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

    # Extract intelligence
    extracted = extract_intelligence(message_text)
    for key in extracted:
        sessions[session_id]["intelligence"][key].extend(extracted[key])

    return {
        "status": "success",
        "scam_detected": scam_detected,
        "reply": reply,
        "session_memory": sessions[session_id]
    }
