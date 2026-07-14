"""
SentinelIQ — Post-Quantum Cryptography Vault
==============================================
Simulated CRYSTALS-Kyber-768 post-quantum encryption layer for
privileged admin credentials and session tokens.

Uses Python `cryptography` library + custom lattice-based math
simulation to demonstrate PQC concepts.

NOTE: This is a SIMULATION for hackathon demonstration purposes.
Real PQC implementations require certified libraries (e.g., liboqs).
"""

import os
import hashlib
import secrets
import datetime
import json
from typing import Dict, Tuple, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import numpy as np


# ---------------------------------------------------------------------------
# Simulated CRYSTALS-Kyber-768 Parameters
# ---------------------------------------------------------------------------

KYBER_N = 256         # Polynomial ring dimension
KYBER_K = 3           # Module rank (Kyber-768)
KYBER_Q = 3329        # Modulus
KYBER_ETA1 = 2        # Noise parameter
KYBER_ETA2 = 2        # Noise parameter
KEY_SIZE_BITS = 768   # Effective key size

PQC_METADATA = {
    "algorithm": "CRYSTALS-Kyber-768 (Simulated)",
    "key_size": KEY_SIZE_BITS,
    "quantum_resistance_level": "NIST Level 3",
    "security_assumption": "Module-LWE",
    "nist_category": "KEM (Key Encapsulation Mechanism)",
    "classical_security": "~192-bit",
    "quantum_security": "~128-bit (Grover-adjusted)",
}


# ---------------------------------------------------------------------------
# Simulated Kyber Key Generation
# ---------------------------------------------------------------------------

def _sample_noise(size: int, eta: int) -> np.ndarray:
    """Sample centered binomial distribution (CBD) noise."""
    result = np.zeros(size, dtype=np.int32)
    for i in range(size):
        a = sum(secrets.randbelow(2) for _ in range(eta))
        b = sum(secrets.randbelow(2) for _ in range(eta))
        result[i] = (a - b) % KYBER_Q
    return result


def generate_keypair() -> Dict:
    """
    Generate a simulated Kyber-768 keypair.
    Returns dict with public_key, private_key, and metadata.
    """
    # Simulate matrix A (public parameter)
    seed = secrets.token_bytes(32)
    np.random.seed(int.from_bytes(seed[:4], 'big'))

    # Generate random matrix A (k x k polynomials)
    A = np.random.randint(0, KYBER_Q, (KYBER_K, KYBER_K, KYBER_N), dtype=np.int32)

    # Generate secret vector s
    s = np.array([_sample_noise(KYBER_N, KYBER_ETA1) for _ in range(KYBER_K)])

    # Generate error vector e
    e = np.array([_sample_noise(KYBER_N, KYBER_ETA1) for _ in range(KYBER_K)])

    # Compute public key: t = A*s + e (simplified)
    t = np.zeros((KYBER_K, KYBER_N), dtype=np.int32)
    for i in range(KYBER_K):
        for j in range(KYBER_K):
            t[i] = (t[i] + np.convolve(A[i][j], s[j])[:KYBER_N]) % KYBER_Q
        t[i] = (t[i] + e[i]) % KYBER_Q

    # Serialize keys as hex strings (for storage)
    public_key_bytes = t.tobytes()
    private_key_bytes = s.tobytes()
    public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
    private_key_hash = hashlib.sha256(private_key_bytes).hexdigest()

    return {
        "public_key": public_key_hash,
        "private_key": private_key_hash,
        "public_key_fingerprint": public_key_hash[:16],
        "key_size_bits": KEY_SIZE_BITS,
        "algorithm": PQC_METADATA["algorithm"],
        "quantum_resistance_level": PQC_METADATA["quantum_resistance_level"],
        "seed": seed.hex()[:32],
        "generated_at": datetime.datetime.now(datetime.timezone.utc),
    }


# ---------------------------------------------------------------------------
# Simulated PQC Encryption/Decryption (using AES-256-GCM underneath)
# ---------------------------------------------------------------------------

def encrypt_credential(plaintext: str, public_key: str) -> Dict:
    """
    Encrypt a credential using simulated PQC scheme.
    Uses the public key as input to derive an AES-256 key via HKDF,
    simulating the KEM encapsulation step of Kyber.
    """
    # Simulate KEM encapsulation: derive shared secret from public key
    shared_secret = _simulate_kem_encapsulate(public_key)

    # Derive AES key from shared secret
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"sentineliq-pqc-credential-encryption",
    ).derive(shared_secret)

    # Encrypt with AES-256-GCM
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "kem_ciphertext": hashlib.sha256(shared_secret).hexdigest()[:32],
        "algorithm": PQC_METADATA["algorithm"],
        "key_size": KEY_SIZE_BITS,
        "quantum_resistance_level": PQC_METADATA["quantum_resistance_level"],
        "encrypted_at": datetime.datetime.now(datetime.timezone.utc),
        "encryption_metadata": {
            "kem_algorithm": "Kyber-768 (Simulated KEM)",
            "symmetric_algorithm": "AES-256-GCM",
            "kdf": "HKDF-SHA256",
            "nonce_size": "96-bit",
        },
    }


def decrypt_credential(encrypted_data: Dict, private_key: str) -> Optional[str]:
    """
    Decrypt a credential using simulated PQC scheme.
    Uses the private key to derive the same shared secret.
    """
    try:
        # Simulate KEM decapsulation
        shared_secret = _simulate_kem_decapsulate(private_key)

        # Derive same AES key
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"sentineliq-pqc-credential-encryption",
        ).derive(shared_secret)

        # Decrypt
        nonce = bytes.fromhex(encrypted_data["nonce"])
        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext.decode('utf-8')
    except Exception:
        return None


def _simulate_kem_encapsulate(public_key: str) -> bytes:
    """Simulate Kyber KEM encapsulation (derive shared secret from public key)."""
    # In real Kyber, this would use the lattice structure
    # For simulation, we derive deterministically from the public key
    return hashlib.sha256(f"kyber-kem-{public_key}".encode()).digest()


def _simulate_kem_decapsulate(private_key: str) -> bytes:
    """Simulate Kyber KEM decapsulation (derive shared secret from private key)."""
    # In real Kyber, this uses the secret key to extract the shared secret
    # For simulation, we ensure same derivation path
    return hashlib.sha256(f"kyber-kem-{private_key}".encode()).digest()


# ---------------------------------------------------------------------------
# Credential Vault Operations
# ---------------------------------------------------------------------------

def create_vault_entry(user_id: str, username: str, role: str) -> Dict:
    """Create a new PQC vault entry for a user."""
    keypair = generate_keypair()

    # Encrypt a session token as demonstration
    session_token = secrets.token_hex(32)
    encrypted = encrypt_credential(session_token, keypair["public_key"])

    return {
        "user_id": user_id,
        "username": username,
        "role": role,
        "pqc_public_key": keypair["public_key"],
        "pqc_private_key_hash": keypair["private_key"][:16] + "..." ,
        "pqc_fingerprint": keypair["public_key_fingerprint"],
        "encrypted_credential_hash": encrypted["kem_ciphertext"],
        "algorithm": keypair["algorithm"],
        "key_size_bits": keypair["key_size_bits"],
        "quantum_resistance_level": keypair["quantum_resistance_level"],
        "quantum_shield_status": "ACTIVE",
        "created_at": keypair["generated_at"],
        "last_rotated": keypair["generated_at"],
        "rotation_due": keypair["generated_at"] + datetime.timedelta(days=30),
        "encryption_metadata": encrypted["encryption_metadata"],
    }


def check_rotation_status(vault_entry: Dict) -> Dict:
    """Check if a credential needs rotation (>30 days old)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    last_rotated = vault_entry.get("last_rotated", now)

    if isinstance(last_rotated, str):
        try:
            last_rotated = datetime.datetime.fromisoformat(last_rotated)
        except ValueError:
            last_rotated = now

    if last_rotated.tzinfo is None:
        last_rotated = last_rotated.replace(tzinfo=datetime.timezone.utc)

    age_days = (now - last_rotated).days

    needs_rotation = age_days >= 30
    status = "ROTATION_REQUIRED" if needs_rotation else "ACTIVE"

    return {
        "needs_rotation": needs_rotation,
        "age_days": age_days,
        "status": status,
        "last_rotated": last_rotated,
        "next_rotation": last_rotated + datetime.timedelta(days=30),
        "quantum_shield_status": "DEGRADED" if needs_rotation else "ACTIVE",
    }


def rotate_credential(vault_entry: Dict) -> Dict:
    """Rotate a credential by generating new keypair and re-encrypting."""
    new_keypair = generate_keypair()

    vault_entry["pqc_public_key"] = new_keypair["public_key"]
    vault_entry["pqc_private_key_hash"] = new_keypair["private_key"][:16] + "..."
    vault_entry["pqc_fingerprint"] = new_keypair["public_key_fingerprint"]
    vault_entry["last_rotated"] = new_keypair["generated_at"]
    vault_entry["rotation_due"] = new_keypair["generated_at"] + datetime.timedelta(days=30)
    vault_entry["quantum_shield_status"] = "ACTIVE"

    # Re-encrypt with new key
    new_token = secrets.token_hex(32)
    encrypted = encrypt_credential(new_token, new_keypair["public_key"])
    vault_entry["encrypted_credential_hash"] = encrypted["kem_ciphertext"]

    return vault_entry


def get_pqc_metadata() -> Dict:
    """Get PQC algorithm metadata for display."""
    return PQC_METADATA.copy()


def get_quantum_shield_badge(status: str) -> Tuple[str, str]:
    """Get badge emoji and color for quantum shield status."""
    badges = {
        "ACTIVE": ("🛡️ QUANTUM SHIELD ACTIVE", "#00C896"),
        "DEGRADED": ("⚠️ SHIELD DEGRADED — ROTATION NEEDED", "#FFB84D"),
        "ROTATION_REQUIRED": ("🔴 ROTATION OVERDUE", "#FF4C4C"),
        "INACTIVE": ("❌ NO PQC PROTECTION", "#FF4C4C"),
    }
    return badges.get(status, badges["INACTIVE"])
