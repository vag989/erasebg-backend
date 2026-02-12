import resend

from erasebg.settings import RESEND_API_KEY, NOTIFICATIONS_EMAIL_ID
from erasebg.api.CONFIG import MESSAGES


def send_verification_email(to_email: str, verification_token: str):
    """
    Send verification email using Resend
    """
    verification_link = f"https://erasebg.co/api/users/verify-email/?verification_token={verification_token}&email={to_email}"
    html_body = get_verfication_email_content(verification_link)

    send_email(
        NOTIFICATIONS_EMAIL_ID,
        to_email,
        MESSAGES["EMAIL_VERIFICATION_SUBJECT"],
        html_body,
    )


def send_password_reset_otp(to_email: str, otp: str):
    """
    Send OTP email using Resend
    """
    html_body = get_otp_email_content(otp)

    send_email(
        NOTIFICATIONS_EMAIL_ID,
        to_email,
        MESSAGES["PASSWORD_RESET_OTP_SUBJECT"],
        html_body,
    )


def send_email(from_email: str, to_email: str, subject: str, html_body: str):
    """
    Send email using Resend
    """
    resend.api_key = RESEND_API_KEY

    params: resend.Emails.SendParams = {
        "from": f"Auth <{from_email}>",
        "to": [""],
        "subject": subject,
        "html": html_body,
    }

    resend.Email.send(params)


def get_verfication_email_content(verification_link: str) -> str:
    """
    Generate the HTML content for the verification email.
    """
    return f"""
    <html>
        <body>
            <h1>Email Verification</h1>
            <p>Thank you for signing up! Please verify your email by clicking the link below:</p>
            <a href="{verification_link}">Verify Email</a>
            <p>If you did not sign up for this account, please ignore this email.</p>
        </body>
    </html>
    """


def get_otp_email_content(otp: str) -> str:
    """
    Generate the HTML content for the OTP email.
    """
    return f"""
    <html>
        <body>
            <h1>Your OTP Code</h1>
            <p>Your One-Time Password (OTP) is: <strong>{otp}</strong></p>
            <p>This OTP is valid for a limited time. If you did not request this, please ignore this email.</p>
        </body>
    </html>
    """
