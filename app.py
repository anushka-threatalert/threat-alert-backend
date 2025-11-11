"""
Threat Alert Backend (Flask + SQLite)
Run: python app.py
"""

import os
import time
import queue
import threading
from datetime import datetime

from flask import Flask, request, jsonify, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv

# Load .env
load_dotenv()

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return jsonify({"message": "Threat Alert System Running"})


# In-memory "database"
threats = []



@app.route('/add_threat', methods=['POST'])
def add_threat():
    data = request.get_json()
    if not data or 'message' not in data or 'level' not in data:
        return jsonify({"error": "Invalid data"}), 400

    # Add to list
    threats.append(data)
    return jsonify({"status": "Threat added", "data": data}), 201

@app.route('/get_threats', methods=['GET'])
def get_threats():
    return jsonify(threats)


# Config
DB_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite")
app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# In-memory queue for SSE alerts
alert_queue = queue.Queue()

# --------------------
# Models
# --------------------
class ThreatLog(db.Model):
    __tablename__ = "threat_logs"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), nullable=False)
    attack_type = db.Column(db.String(64), nullable=False)
    severity = db.Column(db.String(20), default="medium")
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="active")  # active | resolved | ignored

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
        }


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), nullable=False, unique=True)
    reason = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"id": self.id, "ip": self.ip, "reason": self.reason, "timestamp": self.timestamp.isoformat()}


# --------------------
# Helpers
# --------------------
def send_alert_notification(threat: ThreatLog):
    """
    Mock alert sender: place alert in the alert queue (for SSE)
    and optionally send real email if configured.
    """
    payload = {
        "id": threat.id,
        "ip": threat.ip,
        "attack_type": threat.attack_type,
        "severity": threat.severity,
        "details": threat.details,
        "timestamp": threat.timestamp.isoformat(),
        "status": threat.status,
    }

    # --- Optional: Send SMS Alert via Twilio ---
    if threat.severity.lower() == "high":
        try:
            from twilio.rest import Client

            twilio_sid = os.getenv("TWILIO_ACCOUNT_SID")
            twilio_token = os.getenv("TWILIO_AUTH_TOKEN")
            from_num = os.getenv("TWILIO_PHONE")
            to_num = os.getenv("ALERT_PHONE")

            client = Client(twilio_sid, twilio_token)
            sms = client.messages.create(
                body=f"[ALERT] {threat.attack_type} detected from {threat.ip} (Severity: {threat.severity})",
                from_=from_num,
                to=to_num,
            )

            print(f"[SMS SENT] SID: {sms.sid}")
        except Exception as e:
            print("[ALERT] Failed to send SMS:", e)

    # Put into the in-memory SSE queue
    alert_queue.put(payload)

    # For now, just print to console.
    print(f"[ALERT] {threat.attack_type} from {threat.ip} at {threat.timestamp.isoformat()} (severity={threat.severity})")

    # Optional: send email if enabled (simple SMTP can be added here)
    if os.getenv("ALERT_EMAIL_ENABLED", "false").lower() in ("1", "true", "yes"):
        try:
            import smtplib
            from email.message import EmailMessage

            smtp_host = os.getenv("SMTP_HOST")
            smtp_port = int(os.getenv("SMTP_PORT", "587"))
            smtp_user = os.getenv("SMTP_USER")
            smtp_pass = os.getenv("SMTP_PASS")
            to_email = os.getenv("ALERT_TO_EMAIL")

            msg = EmailMessage()
            msg["Subject"] = f"[Threat Alert] {threat.attack_type} from {threat.ip}"
            msg["From"] = smtp_user
            msg["To"] = to_email
            msg.set_content(f"Threat detected:\n\n{payload}")

            with smtplib.SMTP(smtp_host, smtp_port) as s:
                s.starttls()
                s.login(smtp_user, smtp_pass)
                s.send_message(msg)

            print("[ALERT] Email notification sent.")
        except Exception as exc:
            print("[ALERT] Failed to send email:", exc)


# --------------------
# API Endpoints
# --------------------

@app.route("/ping")
def ping():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


@app.route("/logs", methods=["POST"])
def create_log():
    """
    Receive a threat log. Example JSON payload:
    {
      "ip": "1.2.3.4",
      "attack_type": "SQL Injection",
      "severity": "high",
      "details": "payload in query param 'id' "
    }
    """
    data = request.get_json() or {}
    ip = data.get("ip")
    attack_type = data.get("attack_type") or "unknown"
    severity = data.get("severity") or "medium"
    details = data.get("details")

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    t = ThreatLog(ip=ip, attack_type=attack_type, severity=severity, details=details)
    db.session.add(t)
    db.session.commit()

    # send alert (mock)
    send_alert_notification(t)

    # Optionally auto-block based on severity (example rule)
    if severity.lower() == "high":
        try:
            block_ip_internal(ip, reason=f"Auto-block: {attack_type} (severity {severity})")
        except Exception:
            pass

    return jsonify({"message": "log saved", "log": t.to_dict()}), 201


@app.route("/logs", methods=["GET"])
def list_logs():
    """
    Query params:
      ?status=active/resolved
      ?limit=100
    """
    status = request.args.get("status")
    limit = int(request.args.get("limit", 200))
    q = ThreatLog.query
    if status:
        q = q.filter_by(status=status)
    logs = q.order_by(ThreatLog.timestamp.desc()).limit(limit).all()
    return jsonify([l.to_dict() for l in logs])


@app.route("/alerts", methods=["GET"])
def list_alerts():
    """
    For this basic design, alerts are just threat logs with status 'active' or 'resolved'.
    """
    limit = int(request.args.get("limit", 100))
    q = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(limit)
    return jsonify([l.to_dict() for l in q.all()])


# Block IP endpoints
def block_ip_internal(ip, reason=None):
    # Helper to add to BlockedIP if not present
    existing = BlockedIP.query.filter_by(ip=ip).first()
    if existing:
        return existing
    b = BlockedIP(ip=ip, reason=reason)
    db.session.add(b)
    db.session.commit()
    print(f"[BLOCK] {ip} blocked. Reason: {reason}")
    return b


@app.route("/block-ip", methods=["POST"])
def block_ip():
    """
    Payload: { "ip": "1.2.3.4", "reason": "suspicious activity" }
    """
    data = request.get_json() or {}
    ip = data.get("ip")
    reason = data.get("reason", "manual block")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    b = block_ip_internal(ip, reason=reason)
    return jsonify({"message": "blocked", "blocked": b.to_dict()}), 201


@app.route("/blocked", methods=["GET"])
def get_blocked():
    items = BlockedIP.query.order_by(BlockedIP.timestamp.desc()).all()
    return jsonify([i.to_dict() for i in items])


@app.route("/resolve/<int:log_id>", methods=["POST"])
def resolve_log(log_id):
    t = ThreatLog.query.get(log_id)
    if not t:
        return jsonify({"error": "not found"}), 404
    t.status = "resolved"
    db.session.commit()
    return jsonify({"message": "resolved", "log": t.to_dict()})


# SSE stream for real-time alerts
@app.route("/stream")
def stream():
    def event_stream():
        # Keep the connection alive and yield alerts when they arrive.
        while True:
            try:
                payload = alert_queue.get(timeout=60)
                yield f"data: {payload}\n\n"
            except queue.Empty:
                # send a heartbeat to keep connection alive
                yield ":\n\n"
    # Note: using stream_with_context ensures context is available
    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")


# Simple simulation endpoint to generate fake logs for testing
@app.route("/logs", methods=["POST"])
def create_log():
    data = request.get_json() or {}
    ip = data.get("ip")
    attack_type = data.get("attack_type") or "unknown"
    severity = data.get("severity") or "medium"
    details = data.get("details")

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    t = ThreatLog(ip=ip, attack_type=attack_type, severity=severity, details=details)
    db.session.add(t)
    db.session.commit()

    # Send alert to frontend and console
    send_alert_notification(t)

    # 🧾 Prepare and send SMS alert
    message = f"⚠️ Threat detected!\nIP: {ip}\nType: {attack_type}\nSeverity: {severity}\nDetails: {details}"
    try:
        send_sms_alert(message)
        print("[SMS] Alert sent successfully.")
    except Exception as e:
        print("[SMS] Failed to send alert:", e)

    # Optionally auto-block based on severity
    if severity.lower() == "high":
        try:
            block_ip_internal(ip, reason=f"Auto-block: {attack_type} (severity {severity})")
        except Exception:
            pass

    return jsonify({"message": "log saved and SMS sent", "log": t.to_dict()}), 201


from twilio.rest import Client
import os

TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_PHONE_NUMBER")
TO_NUMBER = "+91XXXXXXXXXX"  # <-- your verified phone number


client = Client(TWILIO_SID, TWILIO_TOKEN)

def send_sms_alert(message):
    client.messages.create(
        body=message,
        from_=TWILIO_FROM,
        to=TO_NUMBER
    )

# --------------------
# Init
# --------------------
def init_db():
    with app.app_context():
        db.create_all()
        print("DB initialized / tables created.")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
