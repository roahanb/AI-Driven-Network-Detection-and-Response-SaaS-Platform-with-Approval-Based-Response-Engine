import smtplib
import logging
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List

from app.config import settings

logger = logging.getLogger(__name__)


async def send_email_alert(
    to_emails: List[str],
    subject: str,
    body_html: str,
) -> bool:
    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.warning("SMTP not configured. Skipping email notification.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = ", ".join(to_emails)
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.EMAIL_FROM, to_emails, msg.as_string())

        logger.info(f"Email alert sent to {to_emails}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False


async def send_slack_alert(
    webhook_url: str,
    incident_id: int,
    risk_level: str,
    alert_type: str,
    source_ip: str,
    summary: str,
) -> bool:
    if not webhook_url:
        return False

    color_map = {
        "Critical": "#FF0000",
        "High": "#FF6600",
        "Medium": "#FFCC00",
        "Low": "#00CC00",
    }
    color = color_map.get(risk_level, "#CCCCCC")

    payload = {
        "text": f":rotating_light: *New {risk_level} Security Incident #{incident_id}*",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Alert Type", "value": alert_type, "short": True},
                    {"title": "Risk Level", "value": risk_level, "short": True},
                    {"title": "Source IP", "value": source_ip, "short": True},
                    {"title": "Status", "value": "Pending Approval", "short": True},
                    {"title": "Summary", "value": summary[:500], "short": False},
                ],
                "footer": "AI-NDR Platform",
            }
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
        logger.info(f"Slack alert sent for incident #{incident_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")
        return False


def build_incident_email_html(
    incident_id: int,
    risk_level: str,
    alert_type: str,
    source_ip: str,
    destination_ip: str,
    summary: str,
    recommended_action: str,
    dashboard_url: str = "#",
) -> str:
    color_map = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#16a34a",
    }
    color = color_map.get(risk_level, "#6b7280")

    return f"""
    <html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background: {color}; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
        <h2 style="margin:0">🚨 {risk_level} Security Incident #{incident_id}</h2>
    </div>
    <div style="border: 1px solid #e5e7eb; padding: 20px; border-radius: 0 0 8px 8px;">
        <table style="width:100%; border-collapse: collapse;">
            <tr><td style="padding: 8px; font-weight: bold; width: 40%;">Alert Type</td>
                <td style="padding: 8px;">{alert_type}</td></tr>
            <tr style="background:#f9fafb;"><td style="padding: 8px; font-weight: bold;">Source IP</td>
                <td style="padding: 8px;">{source_ip}</td></tr>
            <tr><td style="padding: 8px; font-weight: bold;">Destination IP</td>
                <td style="padding: 8px;">{destination_ip}</td></tr>
            <tr style="background:#f9fafb;"><td style="padding: 8px; font-weight: bold;">Summary</td>
                <td style="padding: 8px;">{summary}</td></tr>
            <tr><td style="padding: 8px; font-weight: bold;">Recommended Action</td>
                <td style="padding: 8px; color: {color}; font-weight: bold;">{recommended_action}</td></tr>
        </table>
        <div style="margin-top: 20px; text-align: center;">
            <a href="{dashboard_url}/incidents/{incident_id}"
               style="background:{color}; color:white; padding:12px 24px;
                      border-radius:6px; text-decoration:none; display:inline-block;">
                Review Incident
            </a>
        </div>
        <p style="color:#6b7280; font-size:12px; margin-top:20px; text-align:center;">
            AI-NDR SaaS Platform — This is an automated security alert.
        </p>
    </div>
    </body></html>
    """
