# Guerrilla Mail — OTP / Verification Code Collection

## Overview

Guerrilla Mail (`guerrillamail.com`) is a disposable temp email service used during auth flows to receive verification codes, OTPs, and account confirmation emails. It's the only working option for headless programmatic email collection — alternatives like `mail.tm` (rate-limited) and `Mailinator` (404s on public inboxes) failed.

## API Endpoints

Base: `https://api.guerrillamail.com/ajax.php`

| Endpoint | Method | Params | Returns |
|----------|--------|--------|---------|
| `f=get_email_address` | GET | — | `{"email_addr": "...", "sid_token": "...", "alias": "..."}` |
| `f=fetch_email` | GET | `email_id`, `sid_token` | `{"count": N, "list": [{...}]}` |
| `f=set_email_user` | GET | `email_user` (prefix), `sid_token` | Updates alias |
| `f=forget_me` | GET | `sid_token` | Expires the session |

## Flow

### 1. Get a temp address

```bash
curl -s "https://api.guerrillamail.com/ajax.php?f=get_email_address"
```

Response:
```json
{
  "email_addr": "someuser@guerrillamail.com",
  "email_hash": "abc123...",
  "sid_token": "def456...",
  "alias": "someuser"
}
```

Save `email_addr` and `sid_token`. The `sid_token` is required for all subsequent calls.

### 2. Use the address in the target signup form

Fill the email field with `email_addr`, submit the form, then poll for the incoming verification email.

### 3. Poll for incoming emails

```bash
curl -s "https://api.guerrillamail.com/ajax.php?f=fetch_email&sid_token=TOKEN"
```

Returns the email list:
```json
{
  "count": 1,
  "list": [
    {
      "mail_id": 12345,
      "mail_from": "noreply@target.com",
      "mail_subject": "Your verification code",
      "mail_excerpt": "Your verification code is...",
      "mail_body": "<html>...<td style='font-size:32px;font-weight:600'>056153</td>...</html>",
      "mail_timestamp": 1719000000
    }
  ]
}
```

The `mail_body` contains the full HTML of the email.

### 4. Extract the verification code

Verification codes are typically 5-6 digit numbers rendered in styled HTML. Common patterns:

```python
import re
import html

body = email["mail_body"]
# Pattern 1: Large styled digits (font-size:32px, font-weight:600)
match = re.search(r'font-size:\d+px;font-weight:\d+[^>]*>(\d{5,6})<', body)
# Pattern 2: Generic digit extraction near "verification" or "code"
match = re.search(r'(?:verif|cod[e]|otp|pin)\D{0,20}?(\d{5,6})', body, re.I)
# Pattern 3: Unwrap HTML entities then search
text = html.unescape(re.sub(r'<[^>]+>', ' ', body))
match = re.search(r'\b(\d{5,6})\b', text)
```

## Code Example

```python
import json, urllib.request, re, html, time

BASE = "https://api.guerrillamail.com/ajax.php"

# Step 1: Get temp address
resp = json.loads(urllib.request.urlopen(f"{BASE}?f=get_email_address").read())
email = resp["email_addr"]
token = resp["sid_token"]

# Step 2: Use email in target signup, then poll for OTP
for _ in range(30):
    time.sleep(3)
    resp = json.loads(urllib.request.urlopen(f"{BASE}?f=fetch_email&sid_token={token}").read())
    if resp["count"] > 0:
        mail_body = resp["list"][0]["mail_body"]
        break
else:
    raise TimeoutError("No email received")

# Step 3: Extract 5-6 digit code
text = html.unescape(re.sub(r'<[^>]+>', ' ', mail_body))
code = re.search(r'\b(\d{5,6})\b', text)
if code:
    print(f"Verification code: {code.group(1)}")
```

## Why Guerrilla Mail?

| Service | Status | Issue |
|---------|--------|-------|
| **Guerrilla Mail** | ✅ Works | Simple REST API, no auth, reliable |
| mail.tm | ❌ Rate-limited | 429 after a few requests |
| Mailinator | ❌ 404s | Public inboxes return 404 in API |
| Temp-Mail | ❌ Login wall | Requires CAPTCHA to get address |
| 10 Minute Mail | ❌ No API | Web-only, no programmatic access |

## Limitations

- Inbox holds only ~20 emails, then auto-expires
- Email address expires after ~1 hour of inactivity
- No IMAP/POP3 — polling only via REST
- Cannot receive attachments reliably
- No SMS/phone verification (for targets that require phone)
- API sometimes returns stale cached results — add random query param to bust cache

## For targets that require phone verification

Some targets (e.g., Ring account creation) present an SMS two-step flow after email verification. The phone step requires a real SIM. Options:
- **Google Voice** — US-only, limited
- **Twilio** — paid, developer-friendly API
- **burner SIM** — physical SIM + forwarding
- **Skip** — some targets allow deferring phone setup (Ring SMS setup at `/users/tsv/sms/switch` can be skipped)
