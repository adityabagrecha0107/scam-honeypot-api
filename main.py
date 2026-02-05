from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re

app = FastAPI()

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
        "account", "blocked", "locked", "urgent", "verify",
        "bank", "upi", "click", "otp", "fraud",
        "security", "breach", "pin", "suspended"
    ]
    msg = message.lower()
    return any(word in msg for word in keywords)

# ================= HUGE REPLY BANK =================
REPLY_BANK = {
    "otp": [
        "I am getting OTP messages repeatedly and I am really confused.",
        "Why am I receiving OTP now when I didn’t request anything?",
        "OTP came twice just now, which one are you talking about?",
        "My phone is slow and OTP messages are delayed.",
        "I have never shared OTP with anyone before.",
        "Can you explain why OTP is required for account safety?",
        "I am scared to share OTP, this feels unsafe.",
        "I received OTP but bank SMS says never share it.",
        "OTP came but my bank app is not opening.",
        "I am outside and network is weak, OTP is not clear.",
        "OTP came from SBI-SMS but message got deleted accidentally.",
        "Why OTP again? I already verified yesterday.",
        "I received multiple OTPs back-to-back, something feels wrong.",
        "OTP screen disappeared, can you resend?",
        "Is OTP really required? My friend says banks never ask this.",
        "OTP message says do not share with anyone.",
        "I am not comfortable sharing OTP without visiting branch.",
        "Why is OTP needed when account is already verified?",
        "OTP came but phone battery is dying.",
        "Can this be verified without OTP?"
    ],

    "threat": [
        "Please don’t block my account, I depend on it daily.",
        "Why sudden block? I used the account this morning.",
        "Can you delay the block for some time?",
        "This is very stressful, I need help understanding this.",
        "I never got any alert before, why block now?",
        "Can you explain calmly what exactly happened?",
        "I am travelling and cannot deal with this right now.",
        "Is there any other way to stop the block?",
        "Why is my account flagged suddenly?",
        "I have bills to pay, please don’t block it.",
        "This sounds serious, I need some time.",
        "Can you confirm if this is really from SBI?",
        "I want to speak to customer care directly.",
        "Is this temporary or permanent block?",
        "Can my account really be blocked without notice?",
        "I didn’t do anything suspicious.",
        "Why was no email sent about this?",
        "This is making me very anxious.",
        "I need assurance my money is safe.",
        "Please explain before taking action."
    ],

    "account": [
        "This account number doesn’t look familiar to me.",
        "Which branch is this account linked to?",
        "Is this my savings or salary account?",
        "I have multiple accounts, which one is this?",
        "Can you confirm IFSC linked to this account?",
        "This number looks incomplete to me.",
        "I don’t remember this account number exactly.",
        "Which city branch is this account from?",
        "I opened account long ago, details are hazy.",
        "Can you tell last transaction amount?",
        "This doesn’t match my passbook.",
        "Why do you already have my account number?",
        "Can you confirm account holder name?",
        "Is this joint account or single?",
        "This account number seems incorrect.",
        "Can you verify using branch name instead?",
        "I don’t have my documents with me.",
        "I need to check my records first.",
        "Please reconfirm account details.",
        "I am not sure this is my account."
    ],

    "fraud": [
        "Which transaction caused this fraud alert?",
        "Which city or device triggered this issue?",
        "Can you tell exact time of suspicious activity?",
        "Was this debit or credit transaction?",
        "Which merchant was involved?",
        "I didn’t get any fraud SMS earlier.",
        "Can you share reference ID of this alert?",
        "This sounds serious, who reported this?",
        "Is this cyber cell related?",
        "Can you confirm your employee ID?",
        "Which department are you calling from?",
        "I want to cross-check with bank branch.",
        "Why was I not informed earlier?",
        "Is my money already debited?",
        "Which account activity looked suspicious?",
        "I want official email confirmation.",
        "Can you slow down and explain clearly?",
        "Is this fraud domestic or international?",
        "How was breach detected?",
        "I need written confirmation."
    ],

    "generic": [
        "I am really confused right now.",
        "Can you please explain again slowly?",
        "I don’t understand what you are saying.",
        "Why am I getting this message suddenly?",
        "This is overwhelming for me.",
        "I need some time to understand this.",
        "Can you explain in simple words?",
        "I am not sure what to do.",
        "This doesn’t make sense to me.",
        "Please help me understand.",
        "Why is this happening today?",
        "I need clarity before proceeding.",
        "This is unexpected.",
        "I am feeling anxious.",
        "Can you reassure me?",
        "I want to be careful.",
        "Please explain once more.",
        "I am worried about my funds.",
        "I don’t want to make a mistake.",
        "This sounds strange."
    ]
}

# ================= ROTATION LOGIC =================
def get_next_reply(session_id: str, category: str) -> str:
    session = sessions[session_id]

    if "reply_index" not in session:
        session["reply_index"] = {}

    idx = session["reply_index"].get(category, 0)
    replies = REPLY_BANK[category]

    reply = replies[idx % len(replies)]
    session["reply_index"][category] = idx + 1

    return reply

# ================= AGENT REPLY =================
def agent_reply(session_id: str, message: str) -> str:
    msg = message.lower()

    if "otp" in msg or "pin" in msg:
        return get_next_reply(session_id, "otp")

    if "blocked" in msg or "locked" in msg or "suspended" in msg:
        return get_next_reply(session_id, "threat")

    if "account number" in msg:
        return get_next_reply(session_id, "account")

    if "fraud" in msg or "security" in msg or "breach" in msg:
        return get_next_reply(session_id, "fraud")

    return get_next_reply(session_id, "generic")

# ================= INTELLIGENCE EXTRACTION =================
def extract_intelligence(text: str):
    return {
        "upi_ids": re.findall(r'\b[\w.-]+@upi\b', text),
        "phone_numbers": re.findall(r'\+91-\d{10}', text),
        "account_numbers": re.findall(r'\b\d{9,18}\b', text)
    }

# ================= API =================
@app.post("/analyze")
def analyze(
    data: RequestBody,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    session_id = data.sessionId
    message_text = data.message.text

    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "intelligence": {
                "upi_ids": [],
                "phone_numbers": [],
                "account_numbers": []
            }
        }

    sessions[session_id]["history"].append({
        "sender": "scammer",
        "text": message_text
    })

    reply = None
    if is_scam(message_text):
        reply = agent_reply(session_id, message_text)
        sessions[session_id]["history"].append({
            "sender": "honeypot",
            "text": reply
        })

    extracted = extract_intelligence(message_text)
    for k in extracted:
        sessions[session_id]["intelligence"][k].extend(extracted[k])

    return {
        "status": "success",
        "reply": reply,
        "session_memory": sessions[session_id]
    }
