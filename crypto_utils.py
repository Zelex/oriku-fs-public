"""
crypto_utils.py — End-to-end encryption layer.

Provides:
  - RSA-4096 keypair generation and PEM serialization
  - AES-256-GCM symmetric encryption/decryption of file data
  - RSA-OAEP wrapping/unwrapping of per-file AES keys
  - Convergent encryption (derive key from content hash for dedup)
  - Deterministic file-ID generation via SHA-256

Only the file owner possesses the RSA private key needed to unwrap the
per-file AES key, so storage nodes never see plaintext.
"""

import base64
import json
import os
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# ---------------------------------------------------------------------------
# Password-based key derivation
# ---------------------------------------------------------------------------

def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit master key from a password using scrypt.

    scrypt is memory-hard, making brute-force attacks expensive.
    Parameters: N=2^16, r=8, p=1 (~0.1s on modern hardware).
    """
    kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def password_encrypt_key(private_pem: bytes, password: str) -> dict:
    """
    Encrypt an RSA private key PEM with a password-derived key.

    Returns a dict with {salt, nonce, ciphertext} — all base64-encoded.
    This can be stored on disk or on the server for cross-device access.
    """
    salt = os.urandom(32)
    master_key = derive_master_key(password, salt)
    nonce = os.urandom(12)
    ct = AESGCM(master_key).encrypt(nonce, private_pem, associated_data=None)
    return {
        "version": 1,
        "kdf": "scrypt",
        "kdf_params": {"n": 2**16, "r": 8, "p": 1},
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
    }


def password_decrypt_key(blob: dict, password: str) -> bytes:
    """
    Decrypt an RSA private key PEM from a password-encrypted blob.

    Raises ValueError if the password is wrong (AES-GCM auth tag fails).
    """
    salt = base64.b64decode(blob["salt"])
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ciphertext"])

    # Support versioned KDF params (future-proof).
    kdf_params = blob.get("kdf_params", {})
    n = kdf_params.get("n", 2**16)
    r = kdf_params.get("r", 8)
    p = kdf_params.get("p", 1)

    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    master_key = kdf.derive(password.encode("utf-8"))

    try:
        return AESGCM(master_key).decrypt(nonce, ct, associated_data=None)
    except Exception:
        raise ValueError("Wrong password or corrupted key file.")


# ---------------------------------------------------------------------------
# Key-pair management
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """Holds an RSA-4096 key-pair with convenience serialisation helpers."""

    _private_key: Optional[rsa.RSAPrivateKey] = field(repr=False, default=None)
    _public_key: Optional[rsa.RSAPublicKey] = field(repr=False, default=None)

    # -- Constructors -------------------------------------------------------

    @classmethod
    def generate(cls) -> "KeyPair":
        private = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        return cls(_private_key=private, _public_key=private.public_key())

    @classmethod
    def from_private_pem(cls, pem: bytes, password: Optional[bytes] = None) -> "KeyPair":
        private = serialization.load_pem_private_key(pem, password=password)
        return cls(_private_key=private, _public_key=private.public_key())

    @classmethod
    def public_only(cls, pem: bytes) -> "KeyPair":
        """Load a *public-key-only* instance (cannot decrypt)."""
        pub = serialization.load_pem_public_key(pem)
        return cls(_private_key=None, _public_key=pub)

    # -- Identity -----------------------------------------------------------

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the public key (used as user-id)."""
        return hashlib.sha256(self.public_pem()).hexdigest()

    # -- Serialisation ------------------------------------------------------

    def private_pem(self, password: Optional[bytes] = None) -> bytes:
        enc = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        )

    def public_pem(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # -- RSA-OAEP wrap / unwrap of AES keys ---------------------------------

    def wrap_key(self, aes_key: bytes) -> bytes:
        """Encrypt an AES key with the RSA public key (OAEP + SHA-256)."""
        return self._public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def unwrap_key(self, wrapped: bytes) -> bytes:
        """Decrypt an AES key with the RSA private key."""
        if self._private_key is None:
            raise PermissionError("Private key not available — cannot unwrap.")
        return self._private_key.decrypt(
            wrapped,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def has_private_key(self) -> bool:
        return self._private_key is not None

    # -- Password-based key management --------------------------------------

    @classmethod
    def generate_and_save(cls, key_dir: str, password: str = None) -> "KeyPair":
        """
        Generate a new keypair and save it to disk.

        If *password* is provided, the private key is encrypted with a
        password-derived key (scrypt) and saved as ``id_rsa.enc`` (JSON).
        The raw private key is NOT written to disk.

        If no password, saves the raw PEM files (legacy mode).

        Always saves the public key as ``id_rsa.pub``.
        """
        kp = cls.generate()
        kd = Path(key_dir)
        kd.mkdir(parents=True, exist_ok=True)

        # Always save public key.
        (kd / "id_rsa.pub").write_bytes(kp.public_pem())

        if password:
            # Encrypt private key with password and save as JSON.
            blob = password_encrypt_key(kp.private_pem(), password)
            (kd / "id_rsa.enc").write_text(json.dumps(blob, indent=2))
        else:
            # Save raw PEM (legacy).
            (kd / "id_rsa").write_bytes(kp.private_pem())

        return kp

    @classmethod
    def load_from_dir(cls, key_dir: str, password: str = None) -> "KeyPair":
        """
        Load a keypair from a key directory.

        Tries in order:
          1. ``id_rsa.enc`` + password → password-encrypted key
          2. ``id_rsa`` → raw PEM (legacy, no password needed)

        Raises FileNotFoundError if no key files exist.
        Raises ValueError if password is wrong.
        """
        kd = Path(key_dir)
        enc_path = kd / "id_rsa.enc"
        raw_path = kd / "id_rsa"

        if enc_path.exists():
            if not password:
                raise ValueError(
                    "Key is password-protected. Provide --password.")
            blob = json.loads(enc_path.read_text())
            private_pem = password_decrypt_key(blob, password)
            return cls.from_private_pem(private_pem)

        if raw_path.exists():
            return cls.from_private_pem(raw_path.read_bytes())

        raise FileNotFoundError(
            f"No key files found in {kd}. "
            f"Run with 'keygen' to create a keypair."
        )

    @classmethod
    def exists_in_dir(cls, key_dir: str) -> bool:
        """Check if any key files exist in the given directory."""
        kd = Path(key_dir)
        return (kd / "id_rsa.enc").exists() or (kd / "id_rsa").exists()

    @classmethod
    def is_password_protected(cls, key_dir: str) -> bool:
        """Check if the key in the directory is password-encrypted."""
        return (Path(key_dir) / "id_rsa.enc").exists()

    # -- Request signing (authentication) -----------------------------------

    def sign(self, data: bytes) -> bytes:
        """Sign *data* with the RSA private key (PSS + SHA-256)."""
        if self._private_key is None:
            raise PermissionError("Private key not available — cannot sign.")
        return self._private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against the public key. Returns True/False."""
        try:
            self._public_key.verify(
                signature,
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @classmethod
    def verify_with_pem(cls, public_pem: bytes, data: bytes,
                        signature: bytes) -> bool:
        """Verify a signature given a raw PEM public key."""
        kp = cls.public_only(public_pem)
        return kp.verify(data, signature)


# ---------------------------------------------------------------------------
# Symmetric (AES-256-GCM) file encryption
# ---------------------------------------------------------------------------

def generate_file_key() -> bytes:
    """Return a fresh random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def convergent_key(plaintext: bytes) -> bytes:
    """
    Derive a deterministic AES-256 key from the content itself.

    This is *convergent encryption* (aka content-hash keying): identical
    plaintext always produces identical ciphertext, enabling cross-user
    deduplication without the server ever seeing plaintext.

    Trade-off: vulnerable to confirmation-of-a-file attacks (an adversary who
    already possesses the file can verify that you store it).  Wuala accepted
    this trade-off.  Use ``generate_file_key()`` for sensitive files.
    """
    return hashlib.sha256(plaintext).digest()  # 32 bytes = 256 bits


def encrypt_blob(plaintext: bytes, key: bytes,
                  chunk_index: int = None) -> Tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns ``(nonce, ciphertext)``.

    If *chunk_index* is provided (for chunked files that share one key),
    the nonce is derived deterministically: 4 random bytes + 4 bytes of
    chunk_index + 4 random bytes.  This guarantees uniqueness across chunks
    while keeping 8 bytes of randomness to prevent prediction.

    For single-blob encryption (chunk_index=None), a fully random 96-bit
    nonce is used.
    """
    if chunk_index is not None:
        import struct
        nonce = (os.urandom(4)
                 + struct.pack("!I", chunk_index)
                 + os.urandom(4))
    else:
        nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct


def decrypt_blob(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt and authenticate an AES-256-GCM blob."""
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# Content addressing
# ---------------------------------------------------------------------------

def content_hash(data: bytes) -> str:
    """SHA-256 hex digest of arbitrary data (used for content addressing)."""
    return hashlib.sha256(data).hexdigest()


def file_id_for(owner_fingerprint: str, logical_path: str) -> str:
    """
    Derive a deterministic file-ID from the owner's fingerprint and the
    logical file path.  Two different users storing ``/data.txt`` get
    different IDs.
    """
    return hashlib.sha256(
        (owner_fingerprint + ":" + logical_path).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Metadata encryption
# ---------------------------------------------------------------------------

def derive_metadata_key(master_key: bytes, purpose: str = "metadata") -> bytes:
    """
    Derive a 256-bit key for encrypting file metadata (paths, filenames).

    Uses HKDF-SHA256 with a purpose label so the same master key produces
    different subkeys for different uses.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=purpose.encode("utf-8"),
    ).derive(master_key)


def encrypt_metadata(plaintext_str: str, meta_key: bytes) -> str:
    """
    Encrypt a metadata string (e.g. logical path) with AES-256-GCM.

    Returns a URL-safe base64 string: base64(nonce + ciphertext).
    The tracker stores this opaque blob — it cannot read the filename.
    """
    nonce = os.urandom(12)
    ct = AESGCM(meta_key).encrypt(nonce, plaintext_str.encode("utf-8"),
                                   associated_data=None)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_metadata(encrypted_str: str, meta_key: bytes) -> str:
    """
    Decrypt a metadata string previously encrypted with encrypt_metadata().

    Returns the original plaintext string.
    """
    raw = base64.urlsafe_b64decode(encrypted_str)
    nonce = raw[:12]
    ct = raw[12:]
    return AESGCM(meta_key).decrypt(nonce, ct, associated_data=None).decode("utf-8")


# ---------------------------------------------------------------------------
# Cryptree — hierarchical folder key derivation
# ---------------------------------------------------------------------------

def derive_folder_key(parent_key: bytes, folder_name: str) -> bytes:
    """
    Derive a subfolder's encryption key from its parent's key.

    This is the core of Cryptree: each folder has a symmetric key derived
    from its parent. Sharing a folder key implicitly grants access to all
    descendants, because you can re-derive their keys.

    Uses HKDF-SHA256 with the folder name as the info parameter.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cryptree:" + folder_name.encode("utf-8"),
    ).derive(parent_key)


def derive_path_key(root_key: bytes, path: str) -> bytes:
    """
    Walk a path like "/docs/reports/q1.pdf" and derive the key for the
    deepest component by chaining derive_folder_key() calls.

    The root key protects "/", and each path component derives a child key.
    This means sharing the key for "/docs" lets the grantee derive keys for
    "/docs/reports", "/docs/reports/q1.pdf", etc. — but NOT "/photos".

    Returns the key for the leaf (file or deepest folder).
    """
    parts = [p for p in path.strip("/").split("/") if p]
    key = root_key
    for part in parts:
        key = derive_folder_key(key, part)
    return key


def derive_folder_key_for_path(root_key: bytes, folder_path: str) -> bytes:
    """
    Derive the key for a folder path (not including a filename).

    e.g. derive_folder_key_for_path(root, "/docs/reports") returns the
    key that protects the "/docs/reports" folder.
    """
    return derive_path_key(root_key, folder_path)


# ---------------------------------------------------------------------------
# Cryptree — hierarchical folder-level access control
# ---------------------------------------------------------------------------

class Cryptree:
    """
    Manages a hierarchical key tree for folder-level access control.

    This implements the Cryptree scheme from the Wuala paper: each folder
    has a symmetric key derived from its parent. Sharing a folder key
    implicitly grants access to all descendants. Revocation uses lazy
    re-keying — only re-encrypt when a structural change occurs.

    The tree is rooted at the owner's metadata root key. Each folder path
    like "/docs/reports" gets a deterministic key via HKDF chaining.

    Folder shares are stored separately from per-file shares. A folder
    share entry contains:
      - folder_path: the shared folder
      - grantee_fingerprint: who has access
      - wrapped_folder_key: the folder key wrapped with grantee's RSA pubkey
      - generation: incremented on revocation (lazy re-key)

    When a grantee accesses a file under a shared folder, they:
      1. Unwrap the folder key from the share grant
      2. Derive the file's key: derive_path_key(folder_key, relative_path)
      3. Use this to derive the file-level metadata encryption key
    """

    def __init__(self, root_key: bytes):
        self.root_key = root_key
        # generation counters per folder path — incremented on revocation
        self._generations: dict = {}  # folder_path → int

    def folder_key(self, folder_path: str) -> bytes:
        """Derive the current key for a folder path."""
        base_key = derive_path_key(self.root_key, folder_path)
        gen = self._generations.get(folder_path, 0)
        if gen == 0:
            return base_key
        # Re-derive with generation salt for post-revocation keys.
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"cryptree-gen:{gen}:{folder_path}".encode("utf-8"),
        ).derive(base_key)

    def file_key_from_folder(self, folder_path: str,
                              file_rel_path: str) -> bytes:
        """Derive a file's metadata key from its containing folder's key."""
        fk = self.folder_key(folder_path)
        return derive_path_key(fk, file_rel_path)

    def wrap_folder_key(self, folder_path: str,
                        grantee_pubkey: 'KeyPair') -> str:
        """
        Wrap a folder key for a grantee using their RSA public key.

        Returns base64-encoded wrapped key.

        This is the core of Cryptree sharing: the grantee receives ONE key
        that unlocks the entire folder subtree. They can derive child keys
        for any file or subfolder under this path.
        """
        fk = self.folder_key(folder_path)
        wrapped = grantee_pubkey.wrap_key(fk)
        return base64.b64encode(wrapped).decode("ascii")

    @staticmethod
    def unwrap_folder_key(wrapped_b64: str,
                          private_keypair: 'KeyPair') -> bytes:
        """Unwrap a folder key using the grantee's private key."""
        wrapped = base64.b64decode(wrapped_b64)
        return private_keypair.unwrap_key(wrapped)

    def derive_file_aes_key(self, folder_path: str,
                             file_name: str) -> bytes:
        """
        Derive a per-file AES key from the folder key + filename.

        This allows the folder key holder to decrypt any file in the folder
        without needing the owner's RSA private key.
        """
        fk = self.folder_key(folder_path)
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cryptree-file-key:" + file_name.encode("utf-8"),
        ).derive(fk)

    def revoke(self, folder_path: str) -> int:
        """
        Increment the generation counter for a folder, invalidating
        the old folder key.

        After revocation, new files written to this folder will use a
        new key. Old files remain accessible with the old key until they
        are structurally modified (lazy re-keying, matching Wuala's approach).

        Returns the new generation number.
        """
        gen = self._generations.get(folder_path, 0) + 1
        self._generations[folder_path] = gen
        return gen

    def get_generation(self, folder_path: str) -> int:
        """Get the current generation counter for a folder."""
        return self._generations.get(folder_path, 0)

    def set_generation(self, folder_path: str, gen: int):
        """Set the generation counter (e.g. when loading from tracker)."""
        self._generations[folder_path] = gen

    def is_under_folder(self, file_path: str, folder_path: str) -> bool:
        """Check if a file path falls under a folder path."""
        fp = folder_path.rstrip("/") + "/"
        return file_path.startswith(fp) or file_path == folder_path.rstrip("/")

    def relative_path(self, file_path: str, folder_path: str) -> str:
        """Get the relative path of a file within a shared folder."""
        fp = folder_path.rstrip("/") + "/"
        if file_path.startswith(fp):
            return file_path[len(fp):]
        return file_path


# ---------------------------------------------------------------------------
# Content-addressed file ID for cross-user dedup
# ---------------------------------------------------------------------------

def content_addressed_file_id(data: bytes) -> str:
    """
    Derive a file ID purely from content, independent of owner or path.

    When two users upload identical content with convergent encryption,
    both get the same file_id, enabling cross-user deduplication.
    The shards only need to be stored once.

    Format: "caddr-" prefix + SHA-256 hex digest of the content.
    The prefix distinguishes content-addressed IDs from owner-path-based IDs.
    """
    return "caddr-" + hashlib.sha256(data).hexdigest()
