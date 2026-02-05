from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re

app = FastAPI()

API_KEY = "my_secret_key_123"

# 🧠 Memory
sessions = {}

# Request models
class Message(BaseModel):
    sender: str
    text: str

class RequestBody(BaseModel):
    sessionId: str
    message: Message

# Scam detection
def is_scam(message: str) -> bool:
    keywords = ["account", "blocked", "urgent", "verify", "bank", "upi", "click", "otp"]
    return any(word in message.lower() for word in keywords)

# Agent reply
def agent_reply():
    return "Why is my account being blocked?"

# Intelligence extraction
def extract_intelligence(text: str):
    return {
        "upi_ids": re.findall(r'\b[\w.-]+@upi\b', text),
        "phishing_links": re.findall(r'https?://\S+', text)
    }

# API endpoint
@app.post("/analyze")
def analyze(
    data: RequestBody,
    x_api_key: str = Header(None)
):
    # 🔐 API KEY CHECK
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = data.sessionId
    message = data.message.text
    sender = data.message.sender

    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "intelligence": {
                "upi_ids": [],
                "phishing_links": []
            }
        }

    sessions[session_id]["history"].append({
        "sender": sender,
        "text": message
    })

    scam = is_scam(message)
    reply = None

    if scam:
        reply = agent_reply()
        sessions[session_id]["history"].append({
            "sender": "user",
            "text": reply
        })

    extracted = extract_intelligence(message)
    sessions[session_id]["intelligence"]["upi_ids"].extend(extracted["upi_ids"])
    sessions[session_id]["intelligence"]["phishing_links"].extend(extracted["phishing_links"])

    return {
        "status": "success",
        "reply": reply,
        "session_memory": sessions[session_id]
    }
