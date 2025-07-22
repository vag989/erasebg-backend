"""
Constants and limits 
"""
USERNAME_MIN_LENGTH = 8
USERNAME_MAX_LENGTH = 32

API_TOKEN_MAX_LENGTH = 40

CREDITS_EXPIRY_DAYS = 90

JOB_TOKEN_MAX_LENGTH = 40
JOB_TOKEN_EXPIRY_MINUTES = 10

MAX_WIDTH = 1024
MAX_HEIGHT = 1024

ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp']

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
    "REFRESH_TOKEN_AUTH_FAILED": "Refresh token is incorrect or missing",

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
    "JOB_NOT_EXIST": "Job token provided does not exist.",

    # Credits related
    "CREDITS_ADDED": "credits added succesfully.",
    "CREDITS_ADD_FAILED": "Credits add failed.",
    "CREDITS_AVAILABLE": "Credits available.",
    "CREDITS_UNAVAILABLE": "Credits unavailable.",
    "CREDITS_DEDUCTED": "Credits deducted successfully.",
    "CREDITS_NOT_DEDUCTED": "Credits not deducted.",

    # Database related
    "SYSTEM_UNAVAILABLE": "System busy temporarily. Retry Later.",
}

