We’ll do this in four stages: clean the placeholders, document the actual 018 contract, validate everything, then commit/push. After that we move to the landing page integration.

### 1. Clean the future-service placeholders

Do **not** implement fake Role/Permission/Session clients. Your checkpoint explicitly identifies 020/021/022 as separate services and marks those integrations as future work. 

Keep the files as intentional placeholders with documentation:

```bash id="f8q2m1"
cd /Users/gerald/my_apps/buildos-files/018-buildos-auth-service

cat > app/integrations/role_service.py <<'PY'
"""
Future integration boundary for BuildOS Role Service (020).

Role management is owned by the dedicated Role Service.
No Phase 1 implementation is required here.
"""
PY

cat > app/integrations/permission_service.py <<'PY'
"""
Future integration boundary for BuildOS Permission Service (021).

Permission management is owned by the dedicated Permission Service.
No Phase 1 implementation is required here.
"""
PY

cat > app/integrations/session_service.py <<'PY'
"""
Future integration boundary for BuildOS Session Service (022).

Session lifecycle may be delegated to the dedicated Session Service
in a later phase. Phase 1 session revocation is handled by Auth Service.
"""
PY

cat > app/schemas/security.py <<'PY'
"""
Reserved for future security API schemas.

Phase 1 security behavior is exposed through the authentication,
password, and token APIs.
"""
PY

cat > app/services/security_service.py <<'PY'
"""
Reserved for future centralized security orchestration.

Phase 1 security behavior is implemented by the authentication,
password, and token services.
"""
PY

cat > app/api/v1/security.py <<'PY'
"""
Reserved for future security endpoints.

No Phase 1 security endpoint is currently defined.
"""

from fastapi import APIRouter

router = APIRouter()
PY
```

### 2. Document the real 018 API

Create a proper API contract:

```bash id="s6b1p3"
mkdir -p docs/api
nano docs/api/AUTH_API_CONTRACT.md
```

Paste this:

````markdown
# BuildOS Authentication Service — API Contract

**Service:** `018-buildos-auth-service`  
**API Version:** `v1`  
**Role:** Authentication, credentials, tokens, password lifecycle  
**Canonical user owner:** `019-buildos-user-service`

---

## 1. Responsibility

018 owns:

- Authentication credentials
- Password verification
- Password change/reset
- Login attempt tracking
- Account lockout state
- Access tokens
- Refresh tokens
- Token rotation/revocation
- Authentication events
- Security events

018 does not own canonical user identity.

Canonical user identity is owned by 019.

---

## 2. Service Boundary

```text
Client
   │
   ▼
018 Auth Service
   │
   ├── authentication credentials
   ├── password verification
   ├── access/refresh tokens
   ├── token revocation
   │
   └── internal HTTP
          │
          ▼
019 User Service
   ├── canonical user
   ├── identity
   ├── profile
   └── account status
````

---

## 3. Authentication Endpoints

### Register

```http
POST /api/v1/auth/register
```

Required:

```http
Content-Type: application/json
Idempotency-Key: <unique-key>
```

Request:

```json
{
  "email": "user@example.com",
  "username": "username",
  "password": "password",
  "first_name": "First",
  "last_name": "Last",
  "country": "NG",
  "timezone": "Africa/Lagos",
  "language": "en"
}
```

Flow:

```text
018
 │
 ├── create canonical user
 ▼
019 /internal/v1/users/create
 │
 └── user_id
      ▼
018 credential creation
      ▼
018 token issuance
```

Success:

```http
201 Created
```

Response:

```json
{
  "registered": true,
  "user_id": "UUID",
  "public_id": "usr_...",
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer"
}
```

---

### Login

```http
POST /api/v1/auth/login
```

Request:

```json
{
  "identifier": "user@example.com",
  "password": "password"
}
```

Flow:

```text
identifier
    ↓
019 resolve identity
    ↓
canonical user_id
    ↓
018 credential lookup
    ↓
018 password verification
    ↓
018 token issuance
```

Success:

```http
200 OK
```

Response:

```json
{
  "authenticated": true,
  "user_id": "UUID",
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer"
}
```

---

### Logout

```http
POST /api/v1/auth/logout
```

Request:

```json
{
  "refresh_token": "..."
}
```

The refresh token is revoked by 018.

Success:

```http
200 OK
```

Response:

```json
{
  "revoked": true
}
```

---

## 4. Token Endpoints

### Refresh

```http
POST /api/v1/token/refresh
```

Request:

```json
{
  "refresh_token": "..."
}
```

The supplied refresh token must:

* Be cryptographically valid
* Be unexpired
* Be active
* Exist in the token store
* Match its user subject

Successful refresh rotates the token.

---

### Explicit Revoke

```http
POST /api/v1/token/revoke
```

Request:

```json
{
  "refresh_token": "..."
}
```

Success:

```json
{
  "revoked": true
}
```

---

## 5. Password Endpoints

### Change Password

```http
POST /api/v1/password/change
```

Requires:

```http
Authorization: Bearer <access_token>
```

### Request Password Reset

```http
POST /api/v1/password/reset/request
```

### Confirm Password Reset

```http
POST /api/v1/password/reset/confirm
```

Password hashes never leave 018.

---

## 6. Internal User Service Integration

018 communicates with 019 using:

```http
Authorization: Bearer <internal-api-key>
X-Service-ID: buildos-auth-service
```

### Create User

```http
POST /internal/v1/users/create
```

### Resolve User

```http
POST /internal/v1/users/resolve
```

### User Status

```http
GET /internal/v1/users/{user_id}/status
```

---

## 7. Identity Ownership

018 must never treat email, phone, or username as canonical database ownership.

Instead:

```text
email / phone / username
        ↓
019
        ↓
canonical UUID
        ↓
018
```

The JWT `sub` claim contains the canonical 019 UUID.

---

## 8. JWT Contract

Issuer:

```text
buildos-auth-service
```

Audience:

```text
buildos-api
```

Access token claims include:

```text
sub
iss
aud
iat
exp
jti
token_type
context_type
```

`sub` is the canonical user UUID.

018 issues and validates its own JWTs.

---

## 9. Credential Rules

Credentials are stored only in 018.

Required properties:

```text
password_hash
is_active
is_locked
failed_login_count
locked_until
password_changed_at
last_login_at
```

Passwords are hashed using Argon2.

Plaintext passwords must never be stored or logged.

---

## 10. Token Persistence

Refresh tokens are stored as hashes.

Raw refresh tokens are returned to clients but never persisted.

Refresh rotation:

```text
old refresh token
       ↓
revoked
       ↓
replacement refresh token
```

Reusing a revoked refresh token must fail.

---

## 11. Security Rules

Public clients authenticate with:

```http
Authorization: Bearer <access_token>
```

Internal services authenticate with service credentials.

Cross-user access is prohibited.

Authentication errors must not reveal sensitive account information.

---

## 12. Current Phase 1 Status

Implemented and verified:

```text
✅ Register
✅ 019 canonical user creation
✅ Credential persistence
✅ Login
✅ Access token issuance
✅ Refresh token issuance
✅ Refresh rotation
✅ Token revocation
✅ Logout
✅ Revoked-token replay protection
✅ Password change
✅ Password reset
✅ Login attempt tracking
✅ Account lockout
✅ Authentication/security events
```

Current automated test status:

```text
101 passed
```

---

## 13. Future Service Boundaries

Reserved for later phases:

```text
020 Role Service
021 Permission Service
022 Session Service
```

These are not implemented as fake clients in Phase 1.

---

## 14. Phase 1 Definition of Done

018 is considered Phase 1 complete when:

```text
✅ 019 User Service integration works
✅ Register works against real 019
✅ Login works against real 019
✅ Token issuance works
✅ Refresh works
✅ Logout/revocation works
✅ Password lifecycle works
✅ Automated tests pass
✅ Ruff passes
✅ Mypy passes
✅ Application compiles
✅ API contract documented
✅ Future service boundaries documented
```
