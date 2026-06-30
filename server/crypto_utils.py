"""Fernet encryption for credential secrets at rest.

Key resolution priority (highest to lowest):
1. SWARM_ENCRYPTION_KEY env var (raw base64-encoded Fernet key)
2. SWARM_ENCRYPTION_KEY_PATH env var (path to key file)
3. Default: data/encryption.key alongside the findings database
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger("swarm-crypto")

try:
    from cryptography.fernet import Fernet, InvalidToken

    HAS_CRYPTO = True
except ImportError:
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception  # type: ignore[assignment]
    HAS_CRYPTO = False
    raise ImportError("cryptography package is required. " "Install with: pip install swarm-server[encrypt] or pip install cryptography") from None


def _get_key_path() -> Path:
    env_path = os.environ.get("SWARM_ENCRYPTION_KEY_PATH")
    if env_path:
        p = Path(env_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    base = Path(__file__).parent / "data"
    base.mkdir(parents=True, exist_ok=True)
    return base / "encryption.key"


def _load_or_create_key() -> bytes:
    env_key = os.environ.get("SWARM_ENCRYPTION_KEY")
    if env_key:
        try:
            key = env_key.encode()
            Fernet(key)
            return key
        except Exception as e:
            logger.warning("SWARM_ENCRYPTION_KEY is invalid, falling back to file: %s", e)

    key_path = _get_key_path()
    if key_path.exists():
        return key_path.read_bytes()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    logger.info("Generated new encryption key at %s", key_path)
    return key


def _get_fernet():
    return Fernet(_load_or_create_key())


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    try:
        f = _get_fernet()
        return f.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error("Encryption failed: %s", e)
        raise


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    try:
        f = _get_fernet()
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        logger.error("Decryption failed: invalid token or key mismatch")
        raise
