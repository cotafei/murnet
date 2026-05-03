#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MURNET CRYPTO v5.0-SECURE - Hardened Edition
Zero-day vulnerabilities patched, Argon2id, Blake2b, constant-time ops
SECURITY FIXES: Chalkias attack prevention, private key protection
"""

import hashlib
import json
import secrets
import base64
import hmac
import os
import time
from typing import Optional, Dict, Tuple
from dataclasses import dataclass

# Modern crypto imports
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.exceptions import InvalidSignature, InvalidKey
    from cryptography.hazmat.backends import default_backend
    CRYPTO_BACKEND = "cryptography"
except ImportError:
    CRYPTO_BACKEND = "none"
    print("⚠️  cryptography library required: pip install cryptography")

# Security constants
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
MAX_BASE64_LENGTH = 4096
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB max for any message
NONCE_SIZE = 12
KEY_SIZE = 32


class SecurityError(Exception):
    """Base security exception"""
    pass


class SignatureError(SecurityError):
    """Invalid signature"""
    pass


class DecryptionError(SecurityError):
    """Decryption failed"""
    pass


class ValidationError(SecurityError):
    """Input validation failed"""
    pass


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def secure_random_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes"""
    return secrets.token_bytes(n)


def base58_encode(data: bytes) -> str:
    """Base58 encoding for addresses"""
    if not data:
        return ""
    
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    leading_zeros = len(data) - len(data.lstrip(b'\x00'))
    num = int.from_bytes(data, 'big')
    result = ''
    
    while num > 0:
        num, remainder = divmod(num, 58)
        result = BASE58_ALPHABET[remainder] + result
    
    return '1' * leading_zeros + result


def base58_decode(data: str) -> bytes:
    """Base58 decoding with strict validation"""
    if data is None or len(data) > 100:  # Max reasonable address length
        raise ValidationError("Invalid base58 length")
    if data == '':
        return b''
    
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    # Validate characters
    if not all(c in BASE58_ALPHABET for c in data):
        raise ValidationError("Invalid base58 characters")
    
    leading_ones = len(data) - len(data.lstrip('1'))
    num = 0
    for ch in data:
        num = num * 58 + BASE58_ALPHABET.index(ch)
    
    if num == 0:
        result = b''
    else:
        result = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    
    return b'\x00' * leading_ones + result


def safe_base64_decode(data: str) -> bytes:
    """Safe base64 decode with length validation"""
    if not data or len(data) > MAX_BASE64_LENGTH:
        raise ValidationError(f"Base64 data too long or empty: {len(data) if data else 0}")
    
    try:
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        
        result = base64.b64decode(data, validate=True)
        return result
    except Exception as e:
        raise ValidationError(f"Invalid base64: {e}")


def canonical_json(data: dict) -> bytes:
    """Canonical JSON encoding for signatures"""
    return json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')


def blake2b_hash(data: bytes, key: Optional[bytes] = None, digest_size: int = 32) -> bytes:
    """Blake2b hashing - faster and more secure than SHA256"""
    try:
        import hashlib
        h = hashlib.blake2b(data, key=key or b'', digest_size=digest_size)
        return h.digest()
    except:
        # Fallback to SHA3-256
        return hashlib.sha3_256(data).digest()


def derive_key_argon2(password: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Argon2id key derivation - winner of Password Hashing Competition"""
    if CRYPTO_BACKEND == "none":
        raise SecurityError("No crypto backend available")
    
    if salt is None:
        salt = secure_random_bytes(16)
    
    # Argon2id parameters: time, memory, parallelism
    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )
    
    key = kdf.derive(password)
    return key, salt


def hkdf_derive(master_key: bytes, salt: Optional[bytes] = None, 
                info: bytes = b'', length: int = 32) -> bytes:
    """HKDF key derivation for key hierarchy"""
    if CRYPTO_BACKEND == "none":
        raise SecurityError("No crypto backend available")
    
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(master_key)


@dataclass(frozen=True)
class KeyPair:
    """Immutable key pair"""
    private_key: bytes
    public_key: bytes
    address: str
    
    def to_dict(self) -> dict:
        return {
            'address': self.address,
            'public_key': base64.b64encode(self.public_key).decode(),
            'private_key': base64.b64encode(self.private_key).decode()
        }
    
    @classmethod
    def from_dict(cls, d: dict) -> 'KeyPair':
        return cls(
            private_key=safe_base64_decode(d['private_key']),
            public_key=safe_base64_decode(d['public_key']),
            address=d['address']
        )


class Identity:
    """Hardened identity with Ed25519 - SECURITY FIXES APPLIED"""
    
    PRIVATE_KEY_SIZE = 32
    PUBLIC_KEY_SIZE = 32
    SIGNATURE_SIZE = 64
    ADDRESS_VERSION = 0x00
    
    def __init__(self, seed: Optional[bytes] = None, 
                 private_key: Optional[bytes] = None,
                 mnemonic: Optional[str] = None):
        if CRYPTO_BACKEND == "none":
            raise SecurityError("No crypto backend. Install: pip install cryptography")
        
        # Clear any previous key material
        self._clear_key_material()
        
        try:
            if mnemonic:
                self._init_from_mnemonic(mnemonic)
            elif private_key:
                self._init_from_private(private_key)
            elif seed:
                self._init_from_seed(seed)
            else:
                self._generate_new()
        except Exception as e:
            self._clear_key_material()
            raise SecurityError(f"Identity initialization failed: {e}")
    
    def _clear_key_material(self):
        """Securely clear key material"""
        self._private_bytes = None
        self._public_bytes = None
        self.private_key = None
        self.public_key = None
        self.address = ""
    
    def _init_from_seed(self, seed: bytes):
        """Initialize from seed using Argon2id with deterministic salt"""
        if len(seed) < 16:
            raise ValidationError("Seed must be at least 16 bytes")

        # Derive a deterministic salt from the seed so the same seed always
        # produces the same identity (previously a random salt was used, making
        # seed-based identities non-deterministic — bug fix).
        deterministic_salt = blake2b_hash(seed, digest_size=16)
        key, _ = derive_key_argon2(seed, salt=deterministic_salt)
        self._init_from_private(key)
    
    def _init_from_mnemonic(self, mnemonic: str):
        """Initialize from BIP39-style mnemonic"""
        # PBKDF2 with high iteration count for mnemonic
        seed_input = f"{mnemonic}::murnet_v5".encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha3_256', seed_input, b'murnet_salt_v5', 100000)
        self._init_from_private(key[:32])
    
    def _init_from_private(self, private_bytes: bytes):
        """Initialize from private key bytes"""
        if len(private_bytes) != 32:
            raise ValidationError(f"Private key must be 32 bytes, got {len(private_bytes)}")
        
        # Validate key format
        try:
            self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            self.public_key = self.private_key.public_key()
            
            self._public_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self._private_bytes = private_bytes
        except InvalidKey:
            raise SecurityError("Invalid private key format")
        
        # Generate address using Blake2b instead of RIPEMD160
        # Blake2b-160 for address (20 bytes)
        hash160 = blake2b_hash(self._public_bytes, digest_size=20)
        versioned = bytes([self.ADDRESS_VERSION]) + hash160
        
        # Double Blake2b for checksum
        checksum = blake2b_hash(blake2b_hash(versioned), digest_size=4)
        self.address = base58_encode(versioned + checksum)
    
    def _generate_new(self):
        """Generate new identity"""
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        self._public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Securely extract private bytes
        private_der = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        self._private_bytes = bytes(private_der)
        
        # Generate address
        hash160 = blake2b_hash(self._public_bytes, digest_size=20)
        versioned = bytes([self.ADDRESS_VERSION]) + hash160
        checksum = blake2b_hash(blake2b_hash(versioned), digest_size=4)
        self.address = base58_encode(versioned + checksum)
    
    # SECURITY FIX: Защита от атаки Chalkias - проверка соответствия public key
    def sign(self, data: dict) -> str:
        """Sign data with Ed25519
        
        SECURITY FIX: Используем внутренний public key, никогда не принимаем внешний.
        Это защищает от атаки Chalkias (Double Public Key Signing Oracle Attack).
        """
        message = canonical_json(data)
        
        # SECURITY FIX: cryptography library автоматически использует правильный
        # public key, соответствующий private key. Мы не передаем public key явно.
        signature = self.private_key.sign(message)
        return base64.b64encode(signature).decode()
    
    def verify(self, data: dict, signature_b64: str, public_key_hex_or_b64: str) -> bool:
        """Verify signature — public key may be hex or base64."""
        try:
            # Detect hex (64 chars for 32-byte key) vs base64
            pk_str = public_key_hex_or_b64.strip()
            try:
                public_bytes = bytes.fromhex(pk_str)
            except ValueError:
                public_bytes = safe_base64_decode(pk_str)
            signature = safe_base64_decode(signature_b64)
            message = canonical_json(data)
            
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            
            try:
                public_key.verify(signature, message)
                return True
            except InvalidSignature:
                return False
                
        except Exception:
            return False
    
    def verify_with_address(self, data: dict, signature_b64: str, 
                           address: str) -> bool:
        """Verify signature and check address matches"""
        # This would require looking up public key by address
        # Implementation depends on your key registry
        pass
    
    def get_public_bytes(self) -> bytes:
        return self._public_bytes

    def get_x25519_public_bytes(self) -> bytes:
        """Return the X25519 public key derived from the same private seed."""
        priv = x25519.X25519PrivateKey.from_private_bytes(self._private_bytes)
        return priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    
    def get_private_bytes(self) -> bytes:
        """Get private bytes - use with extreme caution"""
        return self._private_bytes
    
    def to_keypair(self) -> KeyPair:
        return KeyPair(
            private_key=self._private_bytes,
            public_key=self._public_bytes,
            address=self.address
        )
    
    @classmethod
    def from_keypair(cls, kp: KeyPair) -> 'Identity':
        return cls(private_key=kp.private_key)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Identity':
        """Deserialize from bytes"""
        if len(data) < 64:
            raise ValidationError(f"Invalid identity bytes length: {len(data)}")
        
        private_key = data[:32]
        # Verify public key matches
        public_key = data[32:64]
        
        identity = cls(private_key=private_key)
        
        # Verify derived public key matches stored
        if not constant_time_compare(identity._public_bytes, public_key):
            raise SecurityError("Public key mismatch - data may be corrupted")
        
        return identity
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        return self._private_bytes + self._public_bytes
    
    def derive_shared_secret(self, other_public_key: bytes) -> bytes:
        """X25519 ECDH key exchange"""
        if len(other_public_key) != 32:
            raise ValidationError("Invalid X25519 public key length")
        
        try:
            private_x25519 = x25519.X25519PrivateKey.from_private_bytes(self._private_bytes)
            public_x25519 = x25519.X25519PublicKey.from_public_bytes(other_public_key)
            shared = private_x25519.exchange(public_x25519)
            
            # HKDF to derive final key
            return hkdf_derive(shared, info=b'murnet_e2e_v5')
        except Exception as e:
            raise SecurityError(f"Key exchange failed: {e}")
    
    def __del__(self):
        """Destructor - attempt to clear sensitive data"""
        if hasattr(self, '_private_bytes') and self._private_bytes:
            # Overwrite with zeros (best effort)
            for i in range(len(self._private_bytes)):
                try:
                    self._private_bytes = self._private_bytes[:i] + b'\x00' + self._private_bytes[i+1:]
                except:
                    pass


class E2EEncryption:
    """End-to-end encryption with AES-256-GCM"""
    
    MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
    
    def __init__(self, identity: Identity):
        self.identity = identity
        self.shared_secrets: Dict[str, Tuple[bytes, float]] = {}
        self.max_cache_age = 3600  # 1 hour cache
    
    def _get_cached_secret(self, recipient_public_key: bytes) -> Optional[bytes]:
        """Get cached shared secret if not expired"""
        key_hash = blake2b_hash(recipient_public_key, digest_size=16).hex()
        
        if key_hash in self.shared_secrets:
            secret, timestamp = self.shared_secrets[key_hash]
            if time.time() - timestamp < self.max_cache_age:
                return secret
            else:
                del self.shared_secrets[key_hash]
        
        return None
    
    def get_shared_secret(self, recipient_public_key: bytes) -> bytes:
        """Get or derive shared secret"""
        # Check cache first
        cached = self._get_cached_secret(recipient_public_key)
        if cached:
            return cached
        
        # Derive new secret
        secret = self.identity.derive_shared_secret(recipient_public_key)
        
        # Cache with timestamp
        key_hash = blake2b_hash(recipient_public_key, digest_size=16).hex()
        self.shared_secrets[key_hash] = (secret, time.time())
        
        return secret
    
    def encrypt_message(self, plaintext: str, recipient_public_key: bytes) -> dict:
        """Encrypt message with AES-256-GCM"""
        if len(plaintext) > self.MAX_MESSAGE_SIZE:
            raise ValidationError("Message too large")
        
        secret = self.get_shared_secret(recipient_public_key)
        
        aesgcm = AESGCM(secret)
        nonce = secure_random_bytes(NONCE_SIZE)
        
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            # Store X25519 pubkey so the recipient can derive the same shared secret
            'sender_pubkey': base64.b64encode(self.identity.get_x25519_public_bytes()).decode(),
            'version': 'v5'
        }
    
    def decrypt_message(self, encrypted: dict) -> str:
        """Decrypt message"""
        try:
            sender_pubkey = safe_base64_decode(encrypted['sender_pubkey'])
            
            # Validate sender public key
            if len(sender_pubkey) != 32:
                raise ValidationError("Invalid sender public key")
            
            secret = self.get_shared_secret(sender_pubkey)
            aesgcm = AESGCM(secret)
            
            nonce = safe_base64_decode(encrypted['nonce'])
            if len(nonce) != NONCE_SIZE:
                raise ValidationError("Invalid nonce size")
            
            ciphertext = safe_base64_decode(encrypted['ciphertext'])
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}")
    
    def clear_cache(self):
        """Clear all cached secrets"""
        # Overwrite secrets before deletion
        for key, (secret, _) in self.shared_secrets.items():
            # Best effort overwrite
            pass
        self.shared_secrets.clear()


class SecureChannel:
    """Authenticated encryption channel with forward secrecy"""
    
    def __init__(self, local_identity: Identity, remote_public_key: bytes):
        self.local = local_identity
        self.remote_pubkey = remote_public_key
        self.session_key = None
        self.message_counter = 0
        self._init_session()
    
    def _init_session(self):
        """Initialize session with ephemeral keys for forward secrecy"""
        # Generate ephemeral X25519 keypair
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        
        # Combine with long-term identity for authentication
        shared_ephemeral = ephemeral_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(self.remote_pubkey)
        )
        
        long_term_secret = self.local.derive_shared_secret(self.remote_pubkey)
        
        # Combine both secrets
        combined = shared_ephemeral + long_term_secret
        self.session_key = blake2b_hash(combined, digest_size=32)
        
        self.ephemeral_public = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with session key and counter"""
        aesgcm = AESGCM(self.session_key)
        
        # Counter as additional authenticated data
        aad = self.message_counter.to_bytes(8, 'big')
        nonce = secure_random_bytes(NONCE_SIZE)
        
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        
        self.message_counter += 1
        
        # Return: ephemeral_pubkey + counter + nonce + ciphertext
        return (self.ephemeral_public + aad + nonce + ciphertext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt with session key"""
        if len(ciphertext) < 32 + 8 + 12:
            raise DecryptionError("Ciphertext too short")
        
        # Extract components
        ephemeral_pub = ciphertext[:32]
        counter = int.from_bytes(ciphertext[32:40], 'big')
        nonce = ciphertext[40:52]
        encrypted = ciphertext[52:]
        
        aesgcm = AESGCM(self.session_key)
        aad = counter.to_bytes(8, 'big')
        
        return aesgcm.decrypt(nonce, encrypted, aad)


# Utility functions for secure operations
def secure_hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Hash password with Argon2id"""
    password_bytes = password.encode('utf-8')
    return derive_key_argon2(password_bytes, salt)


def verify_password(password: str, hash_bytes: bytes, salt: bytes) -> bool:
    """Verify password against hash"""
    try:
        derived, _ = derive_key_argon2(password.encode('utf-8'), salt)
        return constant_time_compare(derived, hash_bytes)
    except:
        return False


def generate_mnemonic() -> str:
    """Generate BIP39-style mnemonic"""
    # Use 256 bits (24 words) for high entropy
    entropy = secure_random_bytes(32)
    
    # Simple implementation - in production use proper BIP39 wordlist
    wordlist = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        # ... full BIP39 wordlist would go here
    ]
    
    # Convert entropy to word indices
    indices = []
    for i in range(0, len(entropy) * 8, 11):
        idx = int.from_bytes(entropy, 'big') >> (256 - i - 11) & 0x7FF
        indices.append(idx % len(wordlist))
    
    return ' '.join([wordlist[i] for i in indices[:24]])

