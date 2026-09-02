"""
BuildOS Auth Service
Application Constants
"""

# ---------------------------------------------------------------------------
# Authentication contexts
# ---------------------------------------------------------------------------

CONTEXT_PERSONAL = "PERSONAL"
CONTEXT_ORGANIZATION = "ORGANIZATION"


# ---------------------------------------------------------------------------
# Authentication events
# ---------------------------------------------------------------------------

EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILURE = "LOGIN_FAILURE"
EVENT_LOGOUT = "LOGOUT"
EVENT_LOGOUT_ALL = "LOGOUT_ALL"
EVENT_TOKEN_REFRESH = "TOKEN_REFRESH"
EVENT_TOKEN_REVOKED = "TOKEN_REVOKED"


# ---------------------------------------------------------------------------
# Security events
# ---------------------------------------------------------------------------

EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
EVENT_ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
EVENT_PASSWORD_CHANGED = "PASSWORD_CHANGED"
EVENT_PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
EVENT_PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"


# ---------------------------------------------------------------------------
# Authentication failure reasons
# ---------------------------------------------------------------------------

FAILURE_INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
FAILURE_CREDENTIAL_INACTIVE = "CREDENTIAL_INACTIVE"
FAILURE_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
FAILURE_ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
FAILURE_USER_NOT_FOUND = "USER_NOT_FOUND"


# ---------------------------------------------------------------------------
# Token types
# ---------------------------------------------------------------------------

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"

BEARER_TOKEN_TYPE = "bearer"


# ---------------------------------------------------------------------------
# Security severity
# ---------------------------------------------------------------------------

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"
SEVERITY_CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Generic service metadata
# ---------------------------------------------------------------------------

SERVICE_NAME = "buildos-auth-service"
API_VERSION = "v1"
