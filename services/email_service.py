import logging
from config.settings import settings

logger = logging.getLogger(__name__)


class EmailService:
    def send_invite_email(
        self,
        to_email: str,
        org_name: str,
        inviter_name: str,
        accept_url: str,
    ) -> None:
        if not settings.RESEND_API_KEY:
            logger.warning("RESEND_API_KEY not set — skipping invite email to %s", to_email)
            return
        try:
            import resend
            resend.api_key = settings.RESEND_API_KEY
            resend.Emails.send({
                "from": "AutoCritic <noreply@autocritic.io>",
                "to": [to_email],
                "subject": f"You've been invited to join {org_name} on AutoCritic",
                "html": f"""
                <p>Hi,</p>
                <p><strong>{inviter_name}</strong> has invited you to join <strong>{org_name}</strong> on AutoCritic.</p>
                <p><a href="{accept_url}" style="background:#6366f1;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block;">Accept Invitation</a></p>
                <p>This invite expires in 7 days. If you didn't expect this, you can safely ignore it.</p>
                """,
            })
        except Exception as exc:
            logger.error("Failed to send invite email to %s: %s", to_email, exc)
