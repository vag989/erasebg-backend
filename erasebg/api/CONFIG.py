"""
Constants and limits 
"""
USERNAME_MIN_LENGTH = 8
USERNAME_MAX_LENGTH = 32

USER_FL_NAME_MAX_LENGTH = 150

API_TOKEN_MAX_LENGTH = 40

REMEMBER_ME_DAYS = 30

CREDITS_EXPIRY_DAYS = 90

JOB_TOKEN_MAX_LENGTH = 40
JOB_TOKEN_EXPIRY_MINUTES = 10

EMAIL_VERIFICATION_TOKEN_MAX_LENGTH = 40
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10
OTP_MAX_INCORRECT_ATTEMPTS = 5
PASSWORD_RESET_TOKEN_MAX_LENGTH = 40

# Subscription Plans
SUBSCRIPTION_PLANS = [
    ("BAS", "Basic"),
    ("PRO", "Pro"),
    ("PRM", "Pro MAX"),
]
SUBSCRIPTION_TYPE_MAX_LENGTH = 3

# Inference response completion status
INFERENCE_COMPLETION_STATUS = [
    ("FAILED", "Failed to Complete"),
    ("COMPLETE", "Fully Completed"),
]
INFERENCE_COMPLETION_STATUS_MAX_LENGTH = 8

USAGE_TOKEN_DEDUCTION_TYPES = [
    ("NONE", "No Deduction"),
    ("PARTIAL", "Partial Deduction"),
    ("FULL", "Full Deduction"),
]
USAGE_TOKEN_DEDUCTION_TYPE_MAX_LENGTH = 7

MAX_WIDTH = 1024
MAX_HEIGHT = 1024

ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']

DEFAULT_CREDITS_ADDED = 100

DEFAULT_PROMPT = "Erase the background and extract the foreground"

# REMOVE_BG_MODEL = "lucataco/remove-bg:95fcc2a26d3899cd6c2691c900465aaeff466285a65c14638cc5f36f34befaf1"
REMOVE_BG_MODEL = "851-labs/background-remover:a029dff38972b5fda4ec5d75d7d1cd25aeff621d2cf4946a41055d7db66b80bc"

# Messages
MESSAGES = {
    # Sign Up related
    "SIGNUP_SUCCESS_MESSAGE": "User created successfully",

    # Login related
    "LOGIN_SUCCESS_MESSAGE": "Login Successful",
    "LOGIN_FAILED_MESSAGE": "Invalid Credentials",

    # Logout related
    "LOGOUT_SUCCESS_MESSAGE": "Logged out successfully",

    # Access Token generation
    "ACCESS_TOKEN_GENERATED": "Access token generated successfully",
    "ACCESS_TOKEN_GENERATION_FAILED": "Access token generation failed",

    # Validation related
    "VALIDATION_ERROR_USERNAME": f"Username must be between {USERNAME_MIN_LENGTH} and {USERNAME_MAX_LENGTH} characters long and can only contain letters, numbers, and the following special characters: _ . -",

    # Authentication Failed
    "ACCESS_TOKEN_AUTH_FAILED": "Access token is incorrect or missing",
    "REFRESH_TOKEN_MISSING": "Refresh token is missing",
    "REFRESH_TOKEN_INVALID_OR_EXPPIRED": "Refresh token is invalid or expired",

    # RemoveBG Inference realted
    "ERASEBG_SERIALIZATION_FAIL": "Invalid image format",
    "POLL_PREDICTION_SERIALIZATION_FAIL": "Invalid format for replicated prediction id", 
    "FETCH_TIMEOUT_ERROR": "Timed out trying to fetch output",

    # Server internal error
    "INTERNAL_ERROR": "An unknown internal server error has occured",

    # API Token related
    "API_TOKEN_CREATED": "API Token created successfully",
    "API_TOKEN_EXISTS": "API Token already exists",

    # Inference Jobs related
    "JOB_DOES_NOT_EXIST": "Job token provided does not exist.",

    # Credits related
    "CREDITS_ADDED": "credits added succesfully.",
    "CREDITS_ADD_FAILED": "Credits add failed.",
    "CREDITS_AVAILABLE": "Credits available.",
    "CREDITS_UNAVAILABLE": "Credits unavailable.",
    "CREDITS_DEDUCTED": "Credits deducted successfully.",
    "CREDITS_NOT_DEDUCTED": "Credits not deducted.",

    # Database related
    "SYSTEM_UNAVAILABLE": "System busy temporarily. Retry Later.",

    # Update details
    "USER_DETAILS_FETCHED": "User details fetched successfully.",
    "USER_DETAILS_UPDATED": "User details updated successfully.",
    "USER_DETAILS_UPDATE_FAILED": "User details update failed.",
    "USER_DETAILS_NON_UNIQUE_EMAIL": "User with this email already exists.",

    # Password Reset
    "EMAIL_NOT_FOUND": "No user with provided Email.",
    "OTP_SENT": "The OTP has been sent to your email.",
    "OTP_MAX_INCORRECT": "Max OTP incorrect attempts reached. Rengerate OTP.",
    "OTP_NOT_FOUND": "No request for OTP generation.",
    "OTP_VERIFICATION_SUCCESSFUL": "OTP verfied successfully",
    "OTP_VERIFICATION_UNSUCCESSFUL": "OTP verification failed",
    "PASSWORD_UPDATE_SUCCESSFUL": "Password updated.",
    "PASSWORD_UPDATE_TOKEN_INVALID": "Password reset token is invalid",

    # Email templates
    "EMAIL_VERIFICATION_SUBJECT": "FootprintAI - Verify your email address",
    "EMAIL_VERIFICATION_TEMPLATE": "Please clink on the following link to verify your email address: {verification_link} \n\n If you did not create an account, no further action is required.",
    "EMAIL_OTP_SUBJECT": "FootprintAI - Your Password Reset OTP",
    "EMAIL_OTP_TEMPLATE": "Please use the following OTP to reset your password: {otp} \n\n If you did not request a password reset, no further action is required.",
    
    # Email Verification
    "EMAIL_ALREADY_VERIFIED": "Email is already verified.",
    "EMAIL_NOT_VERIFIED_MESSAGE": "Email not verified. Please verify your email to log in.",
    "RESEND_VERIFICATION_EMAIL_SUCCESS": "Verification email resent successfully.",
    "RESEND_VERIFICATION_EMAIL_NOT_FOUND": "No unverified user with provided Email.",
    "RESEND_VERIFICATION_EMAIL_FAILED": "Resend verification email failed.",
}

