"""
Zero-Dependency, Low-Latency ProjectDiscovery Interactsh (OAST) Client.

Implements the full Interactsh encrypted Out-of-Band protocol using only the
Python 3.9+ standard library (with an optional OpenSSL CLI fast-path for ~18ms
RSA-2048 key generation and a pure-Python Miller-Rabin fallback):
  - XID 20-char correlation-id + 13-char nonce generation
  - SubjectPublicKeyInfo (PKIX) PEM encoding & CRT RSA-OAEP-SHA256 decryption
  - Pure-Python FIPS-197 AES-256 + CFB-128 stream decryption
  - Parallel server racing (/register) returning on the fastest responding node
  - Tagged DNS interaction parsing (resolver IP, QType, tag prefix, and EDNS ECS)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

DEFAULT_OAST_SERVERS: Tuple[str, ...] = (
    "oast.pro",
    "oast.fun",
    "oast.me",
    "oast.live",
    "oast.site",
    "oast.online",
)

_XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
_NONCE_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
_ECS_SUBNET_RE = re.compile(r";\s*SUBNET:\s*\[?([0-9a-fA-F:.]+)\]?/(\d+)/(\d+)")


# ---------------------------------------------------------------------------
# Pure-Python FIPS-197 AES (128/192/256) & CFB-128 Stream Decryption
# ---------------------------------------------------------------------------

def _build_aes_tables() -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    """Deterministically generate the 256-byte AES S-Box and xtime GF(2^8) table."""
    gf_exp = [0] * 512
    gf_log = [0] * 256
    x = 1
    for i in range(255):
        gf_exp[i] = x
        gf_log[x] = i
        x ^= (x << 1) ^ (0x11B if (x & 0x80) else 0)
        x &= 0xFF
    for i in range(255, 512):
        gf_exp[i] = gf_exp[i - 255]

    sbox = [0] * 256
    sbox[0] = 0x63
    for a in range(1, 256):
        inv = gf_exp[255 - gf_log[a]]
        s = inv
        for shift in (1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sbox[a] = (s ^ 0x63) & 0xFF

    xtime = [((i << 1) ^ (0x11B if (i & 0x80) else 0)) & 0xFF for i in range(256)]
    return tuple(sbox), tuple(xtime)


_SBOX, _XTIME = _build_aes_tables()
_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _aes_expand_key(key: bytes) -> List[bytes]:
    """Expand a 16/24/32-byte AES key into Nr+1 16-byte round keys."""
    key_len = len(key)
    if key_len not in (16, 24, 32):
        raise ValueError(f"Unsupported AES key length: {key_len} bytes")
    nk = key_len // 4
    nr = nk + 6
    total_words = 4 * (nr + 1)

    w = list(struct.unpack(f"!{nk}I", key))
    for i in range(nk, total_words):
        temp = w[i - 1]
        if i % nk == 0:
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            sub = (
                (_SBOX[(rot >> 24) & 0xFF] << 24)
                | (_SBOX[(rot >> 16) & 0xFF] << 16)
                | (_SBOX[(rot >> 8) & 0xFF] << 8)
                | _SBOX[rot & 0xFF]
            )
            temp = sub ^ (_RCON[i // nk] << 24)
        elif nk > 6 and (i % nk == 4):
            temp = (
                (_SBOX[(temp >> 24) & 0xFF] << 24)
                | (_SBOX[(temp >> 16) & 0xFF] << 16)
                | (_SBOX[(temp >> 8) & 0xFF] << 8)
                | _SBOX[temp & 0xFF]
            )
        w.append(w[i - nk] ^ temp)

    round_keys: List[bytes] = []
    for r in range(nr + 1):
        round_keys.append(struct.pack("!4I", *w[4 * r : 4 * (r + 1)]))
    return round_keys


def _aes_encrypt_block(round_keys: List[bytes], block: bytes) -> bytes:
    """Encrypt a single 16-byte AES block."""
    sbox = _SBOX
    xtime = _XTIME
    rk0 = round_keys[0]
    s = [block[i] ^ rk0[i] for i in range(16)]
    nr = len(round_keys) - 1

    for r in range(1, nr):
        # SubBytes + ShiftRows combined
        t0, t4, t8, t12 = sbox[s[0]], sbox[s[4]], sbox[s[8]], sbox[s[12]]
        t1, t5, t9, t13 = sbox[s[5]], sbox[s[9]], sbox[s[13]], sbox[s[1]]
        t2, t6, t10, t14 = sbox[s[10]], sbox[s[14]], sbox[s[2]], sbox[s[6]]
        t3, t7, t11, t15 = sbox[s[15]], sbox[s[3]], sbox[s[7]], sbox[s[11]]

        rk = round_keys[r]
        # MixColumns + AddRoundKey on all 4 columns
        a0, a1, a2, a3 = t0, t1, t2, t3
        h = a0 ^ a1 ^ a2 ^ a3
        s[0] = a0 ^ h ^ xtime[a0 ^ a1] ^ rk[0]
        s[1] = a1 ^ h ^ xtime[a1 ^ a2] ^ rk[1]
        s[2] = a2 ^ h ^ xtime[a2 ^ a3] ^ rk[2]
        s[3] = a3 ^ h ^ xtime[a3 ^ a0] ^ rk[3]

        a0, a1, a2, a3 = t4, t5, t6, t7
        h = a0 ^ a1 ^ a2 ^ a3
        s[4] = a0 ^ h ^ xtime[a0 ^ a1] ^ rk[4]
        s[5] = a1 ^ h ^ xtime[a1 ^ a2] ^ rk[5]
        s[6] = a2 ^ h ^ xtime[a2 ^ a3] ^ rk[6]
        s[7] = a3 ^ h ^ xtime[a3 ^ a0] ^ rk[7]

        a0, a1, a2, a3 = t8, t9, t10, t11
        h = a0 ^ a1 ^ a2 ^ a3
        s[8] = a0 ^ h ^ xtime[a0 ^ a1] ^ rk[8]
        s[9] = a1 ^ h ^ xtime[a1 ^ a2] ^ rk[9]
        s[10] = a2 ^ h ^ xtime[a2 ^ a3] ^ rk[10]
        s[11] = a3 ^ h ^ xtime[a3 ^ a0] ^ rk[11]

        a0, a1, a2, a3 = t12, t13, t14, t15
        h = a0 ^ a1 ^ a2 ^ a3
        s[12] = a0 ^ h ^ xtime[a0 ^ a1] ^ rk[12]
        s[13] = a1 ^ h ^ xtime[a1 ^ a2] ^ rk[13]
        s[14] = a2 ^ h ^ xtime[a2 ^ a3] ^ rk[14]
        s[15] = a3 ^ h ^ xtime[a3 ^ a0] ^ rk[15]

    # Final round (SubBytes + ShiftRows + AddRoundKey, no MixColumns)
    rk_last = round_keys[nr]
    return bytes(
        (
            sbox[s[0]] ^ rk_last[0],
            sbox[s[5]] ^ rk_last[1],
            sbox[s[10]] ^ rk_last[2],
            sbox[s[15]] ^ rk_last[3],
            sbox[s[4]] ^ rk_last[4],
            sbox[s[9]] ^ rk_last[5],
            sbox[s[14]] ^ rk_last[6],
            sbox[s[3]] ^ rk_last[7],
            sbox[s[8]] ^ rk_last[8],
            sbox[s[13]] ^ rk_last[9],
            sbox[s[2]] ^ rk_last[10],
            sbox[s[7]] ^ rk_last[11],
            sbox[s[12]] ^ rk_last[12],
            sbox[s[1]] ^ rk_last[13],
            sbox[s[6]] ^ rk_last[14],
            sbox[s[11]] ^ rk_last[15],
        )
    )


def aes_ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt/encrypt data using AES-CTR with 128-bit big-endian counter
    (compatible with modern ProjectDiscovery Interactsh Go cipher.NewCTR(block, iv)).
    """
    if len(iv) != 16:
        raise ValueError("AES-CTR IV must be 16 bytes")
    round_keys = _aes_expand_key(key)
    out = bytearray()
    ctr_base = int.from_bytes(iv, "big")
    mask_128 = (1 << 128) - 1
    pos = 0
    block_idx = 0
    total = len(ciphertext)
    while pos < total:
        chunk = ciphertext[pos : pos + 16]
        ctr_bytes = ((ctr_base + block_idx) & mask_128).to_bytes(16, "big")
        ks = _aes_encrypt_block(round_keys, ctr_bytes)
        out.extend(c ^ k for c, k in zip(chunk, ks))
        pos += 16
        block_idx += 1
    return bytes(out)


aes_ctr_encrypt = aes_ctr_decrypt


def aes_cfb128_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-CFB with 128-bit full-block feedback
    (compatible with Go crypto/cipher.NewCFBDecrypter and OpenSSL aes-256-cfb).
    """
    if len(iv) != 16:
        raise ValueError("AES-CFB128 IV must be 16 bytes")
    round_keys = _aes_expand_key(key)
    out = bytearray()
    feedback = iv
    pos = 0
    total = len(ciphertext)
    while pos < total:
        chunk = ciphertext[pos : pos + 16]
        ks = _aes_encrypt_block(round_keys, feedback)
        out.extend(c ^ k for c, k in zip(chunk, ks))
        feedback = chunk
        pos += 16
    return bytes(out)


def aes_cfb128_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-CFB with 128-bit full-block feedback (for tests)."""
    if len(iv) != 16:
        raise ValueError("AES-CFB128 IV must be 16 bytes")
    round_keys = _aes_expand_key(key)
    out = bytearray()
    feedback = iv
    pos = 0
    total = len(plaintext)
    while pos < total:
        chunk = plaintext[pos : pos + 16]
        ks = _aes_encrypt_block(round_keys, feedback)
        ct_chunk = bytes(p ^ k for p, k in zip(chunk, ks))
        out.extend(ct_chunk)
        feedback = ct_chunk
        pos += 16
    return bytes(out)


# ---------------------------------------------------------------------------
# RSA-2048 Key Generation, ASN.1 DER SPKI Encoding & RSA-OAEP-SHA256
# ---------------------------------------------------------------------------

def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(lb)]) + lb


def _der_int(val: int) -> bytes:
    raw = val.to_bytes(max(1, (val.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _der_seq(content: bytes) -> bytes:
    return b"\x30" + _der_len(len(content)) + content


def _read_der_element(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """Read a single ASN.1 DER TLV element; returns (tag, value_bytes, next_offset)."""
    if offset >= len(data):
        raise ValueError("Unexpected EOF reading ASN.1 DER")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Truncated ASN.1 DER length")
    first_len = data[offset]
    offset += 1
    if (first_len & 0x80) == 0:
        length = first_len
    else:
        num_bytes = first_len & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise ValueError("Invalid ASN.1 DER long-form length")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    if offset + length > len(data):
        raise ValueError("Truncated ASN.1 DER value")
    return tag, data[offset : offset + length], offset + length


def encode_rsa_spki_pem(n: int, e: int) -> bytes:
    """Encode RSA (n, e) into RFC 5280 SubjectPublicKeyInfo PEM ('BEGIN PUBLIC KEY')."""
    pkcs1_pub = _der_seq(_der_int(n) + _der_int(e))
    # OID 1.2.840.113549.1.1.1 (rsaEncryption) + NULL
    alg_id = _der_seq(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00")
    bit_str_body = b"\x00" + pkcs1_pub
    bit_str = b"\x03" + _der_len(len(bit_str_body)) + bit_str_body
    spki_der = _der_seq(alg_id + bit_str)

    b64 = base64.b64encode(spki_der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    pem_str = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
    return pem_str.encode("ascii")


@dataclass
class RSAKeyPair:
    """RSA keypair supporting fast CRT decryption and SPKI PEM export."""
    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0
    dp: int = 0
    dq: int = 0
    qinv: int = 0

    @property
    def modulus_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def public_key_pem(self) -> bytes:
        return encode_rsa_spki_pem(self.n, self.e)

    def _raw_decrypt_int(self, c: int) -> int:
        if self.p and self.q and self.dp and self.dq and self.qinv:
            m1 = pow(c, self.dp, self.p)
            m2 = pow(c, self.dq, self.q)
            h = (self.qinv * (m1 - m2)) % self.p
            return m2 + h * self.q
        return pow(c, self.d, self.n)

    def decrypt_oaep_sha256(self, ciphertext: bytes, label: bytes = b"") -> bytes:
        """RFC 8017 Section 7.1.2 RSAES-OAEP-DECRYPT with SHA-256 and MGF1-SHA256."""
        k = self.modulus_bytes
        hlen = 32  # SHA-256 digest size
        if len(ciphertext) != k or k < 2 * hlen + 2:
            raise ValueError(f"Invalid RSA-OAEP ciphertext length ({len(ciphertext)} != {k})")

        c_int = int.from_bytes(ciphertext, "big")
        if c_int >= self.n:
            raise ValueError("RSA-OAEP ciphertext representative out of range")

        m_int = self._raw_decrypt_int(c_int)
        em = m_int.to_bytes(k, "big")

        y = em[0]
        masked_seed = em[1 : 1 + hlen]
        masked_db = em[1 + hlen :]

        seed_mask = _mgf1_sha256(masked_db, hlen)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        db_mask = _mgf1_sha256(seed, k - hlen - 1)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        lhash = hashlib.sha256(label).digest()
        lhash_prime = db[:hlen]

        idx = hlen
        while idx < len(db) and db[idx] == 0x00:
            idx += 1

        sep_ok = idx < len(db) and db[idx] == 0x01
        if y != 0x00 or not hmac.compare_digest(lhash, lhash_prime) or not sep_ok:
            raise ValueError("RSA-OAEP decryption error (padding check failed)")

        return db[idx + 1 :]

    def encrypt_oaep_sha256(self, message: bytes, label: bytes = b"") -> bytes:
        """RFC 8017 Section 7.1.1 RSAES-OAEP-ENCRYPT with SHA-256 (used in unit tests)."""
        k = self.modulus_bytes
        hlen = 32
        max_msg = k - 2 * hlen - 2
        if len(message) > max_msg:
            raise ValueError("Message too long for RSA-OAEP")
        lhash = hashlib.sha256(label).digest()
        ps = b"\x00" * (max_msg - len(message))
        db = lhash + ps + b"\x01" + message
        seed = secrets.token_bytes(hlen)
        db_mask = _mgf1_sha256(seed, k - hlen - 1)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        seed_mask = _mgf1_sha256(masked_db, hlen)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        em = b"\x00" + masked_seed + masked_db
        m_int = int.from_bytes(em, "big")
        c_int = pow(m_int, self.e, self.n)
        return c_int.to_bytes(k, "big")


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + struct.pack("!I", counter)).digest())
        counter += 1
    return bytes(out[:length])


def _parse_rsa_private_pem(pem_bytes: bytes) -> RSAKeyPair:
    """Parse either PKCS#1 ('BEGIN RSA PRIVATE KEY') or PKCS#8 ('BEGIN PRIVATE KEY') PEM."""
    b64_lines = [
        line.strip()
        for line in pem_bytes.decode("ascii", errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    der = base64.b64decode("".join(b64_lines))
    tag, seq_body, _ = _read_der_element(der, 0)
    if tag != 0x30:
        raise ValueError("Invalid DER private key outer sequence")

    # Inspect children of outer SEQUENCE
    children: List[Tuple[int, bytes]] = []
    pos = 0
    while pos < len(seq_body):
        ctag, cval, pos = _read_der_element(seq_body, pos)
        children.append((ctag, cval))

    # PKCS#8 PrivateKeyInfo: [INTEGER version, SEQUENCE algId, OCTET STRING pkcs1_der, ...]
    if len(children) >= 3 and children[1][0] == 0x30 and children[2][0] == 0x04:
        inner_tag, inner_body, _ = _read_der_element(children[2][1], 0)
        if inner_tag != 0x30:
            raise ValueError("Invalid PKCS#1 sequence inside PKCS#8")
        children = []
        pos = 0
        while pos < len(inner_body):
            ctag, cval, pos = _read_der_element(inner_body, pos)
            children.append((ctag, cval))

    if len(children) < 9:
        raise ValueError("Incomplete RSA private key ASN.1 fields")

    ints = [int.from_bytes(cval, "big") for _, cval in children[:9]]
    _, n, e, d, p, q, dp, dq, qinv = ints
    return RSAKeyPair(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)


_SMALL_PRIMES: Tuple[int, ...] = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
    163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
)


def _is_probable_prime(n: int, rounds: int = 8) -> bool:
    if n < 2 or (n & 1) == 0:
        return n == 2
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    # Write n - 1 = d * 2^s
    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits)
        cand |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(cand):
            return cand


def generate_rsa_keypair_pure_python(bits: int = 2048) -> RSAKeyPair:
    """Pure-Python RSA key generator fallback when openssl CLI is unavailable."""
    e = 65537
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        try:
            d = pow(e, -1, phi)
            qinv = pow(q, -1, p)
            break
        except ValueError:
            continue
    n = p * q
    return RSAKeyPair(
        n=n,
        e=e,
        d=d,
        p=p,
        q=q,
        dp=d % (p - 1),
        dq=d % (q - 1),
        qinv=qinv,
    )


def generate_rsa_keypair(bits: int = 2048, prefer_openssl: bool = True) -> RSAKeyPair:
    """
    Generate an RSA-2048 keypair in ~18ms via OpenSSL CLI if available,
    gracefully falling back to pure-Python Miller-Rabin generation.
    """
    if prefer_openssl:
        openssl_bin = shutil.which("openssl")
        if openssl_bin:
            try:
                proc = subprocess.run(
                    [openssl_bin, "genrsa", str(bits)],
                    capture_output=True,
                    timeout=3.0,
                    check=True,
                )
                return _parse_rsa_private_pem(proc.stdout)
            except Exception:
                pass
    return generate_rsa_keypair_pure_python(bits)


# ---------------------------------------------------------------------------
# XID Correlation-ID & Interactsh Session Protocol
# ---------------------------------------------------------------------------

_XID_COUNTER = random.randint(0, 0xFFFFFF)
_XID_LOCK = threading.Lock()


def generate_xid() -> str:
    """
    Generate a genuine 20-character Go rs/xid compatible identifier
    (12 bytes: 4B timestamp + 5B random + 3B counter -> 20 base32hex chars).
    """
    global _XID_COUNTER
    with _XID_LOCK:
        _XID_COUNTER = (_XID_COUNTER + 1) & 0xFFFFFF
        cnt = _XID_COUNTER

    ts = int(time.time()) & 0xFFFFFFFF
    mid_pid = secrets.token_bytes(5)
    raw = (
        struct.pack(">I", ts)
        + mid_pid
        + bytes([(cnt >> 16) & 0xFF, (cnt >> 8) & 0xFF, cnt & 0xFF])
    )
    # 12 bytes = 96 bits -> pad 4 zero bits on right = 100 bits = 20 * 5-bit symbols
    val = int.from_bytes(raw, "big") << 4
    chars = [_XID_ALPHABET[(val >> (95 - 5 * i)) & 0x1F] for i in range(20)]
    return "".join(chars)


def generate_nonce(length: int = 13) -> str:
    return "".join(secrets.choice(_NONCE_ALPHABET) for _ in range(length))


def extract_ip_from_remote_address(addr: str) -> Optional[str]:
    """Extract clean IPv4 or IPv6 address from Interactsh remote-address ('1.2.3.4:53120' or '[2001:db8::1]:53')."""
    if not addr:
        return None
    s = addr.strip()
    if s.startswith("["):
        end = s.find("]")
        if end != -1:
            s = s[1:end]
    elif s.count(":") == 1:
        host_part, port_part = s.rsplit(":", 1)
        if port_part.isdigit():
            s = host_part
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None


def extract_ecs_from_raw_request(raw_req: str) -> Optional[str]:
    """Extract EDNS0 Client Subnet CIDR from miekg/dns String() output ('; SUBNET: 1.2.3.0/24/0')."""
    if not raw_req:
        return None
    m = _ECS_SUBNET_RE.search(raw_req)
    if not m:
        return None
    ip_str, mask_str, _ = m.group(1), m.group(2), m.group(3)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_unspecified:
            return None
        return f"{ip_str}/{mask_str}"
    except ValueError:
        return None


@dataclass
class InteractshInteraction:
    """Single decoded out-of-band interaction captured by the authoritative OAST server."""
    protocol: str
    unique_id: str
    full_id: str
    tag: str
    q_type: str
    remote_ip: str
    ecs_subnet: Optional[str] = None
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "tag": self.tag,
            "q_type": self.q_type,
            "remote_ip": self.remote_ip,
            "ecs_subnet": self.ecs_subnet,
            "timestamp": self.timestamp,
        }


def _parse_interaction_json(
    raw_json: str,
    correlation_id: str,
    uid_tags: Optional[Dict[str, str]] = None,
) -> Optional[InteractshInteraction]:
    try:
        obj = json.loads(raw_json)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None

    proto = str(obj.get("protocol") or "").lower()
    unique_id = str(obj.get("unique-id") or obj.get("unique_id") or "").lower()
    full_id = str(obj.get("full-id") or obj.get("full_id") or "").lower().strip(".")
    q_type = str(obj.get("q-type") or obj.get("q_type") or "").upper()
    remote_raw = str(obj.get("remote-address") or obj.get("remote_address") or "")
    raw_req = str(obj.get("raw-request") or obj.get("raw_request") or "")
    ts = str(obj.get("timestamp") or "")

    remote_ip = extract_ip_from_remote_address(remote_raw)
    if not remote_ip:
        return None

    tag = "untagged"
    if uid_tags:
        if unique_id in uid_tags:
            tag = uid_tags[unique_id]
        elif full_id in uid_tags:
            tag = uid_tags[full_id]
        else:
            for part in full_id.split("."):
                if part in uid_tags:
                    tag = uid_tags[part]
                    break

    if tag == "untagged" and "." in full_id:
        parts = full_id.split(".")
        cid_lower = correlation_id.lower()
        cid_idx = -1
        for i, p in enumerate(parts):
            if p.startswith(cid_lower):
                cid_idx = i
                break
        if cid_idx > 0:
            tag = ".".join(parts[:cid_idx])
        else:
            tag = parts[0]

    ecs = extract_ecs_from_raw_request(raw_req)
    return InteractshInteraction(
        protocol=proto,
        unique_id=unique_id,
        full_id=full_id,
        tag=tag,
        q_type=q_type,
        remote_ip=remote_ip,
        ecs_subnet=ecs,
        timestamp=ts,
    )


def _open_url_resilient(req: urllib.request.Request, timeout: float) -> bytes:
    """Try standard opener (respecting active proxy), with direct fallback on proxy error."""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError:
        raise
    except Exception:
        direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with direct_opener.open(req, timeout=timeout) as resp:
            return resp.read()


@dataclass
class InteractshSession:
    """Active registered Interactsh OAST session."""
    server: str
    correlation_id: str
    secret_key: str
    keypair: RSAKeyPair
    token: Optional[str] = None
    register_latency_ms: float = 0.0
    scheme: str = "https"
    _uid_tags: Dict[str, str] = field(default_factory=dict, repr=False)
    _closed: bool = field(default=False, repr=False)

    def subdomain(self, tag: Optional[str] = None, nonce_len: int = 13) -> str:
        """
        Build a single-label 33-char OAST subdomain (<20cid><13nonce>.<server>)
        and bind its unique_id to `tag` so QNAME-minimized DNS queries preserve
        100% exact channel attribution and match wildcard TLS certificates.
        """
        uid = f"{self.correlation_id}{generate_nonce(nonce_len)}".lower()
        clean_srv = self.server.split("://")[-1].strip("/")
        if tag:
            self._uid_tags[uid] = tag
        return f"{uid}.{clean_srv}"

    def _headers(self, json_body: bool = False) -> Dict[str, str]:
        hdrs = {
            "User-Agent": "Interactsh-Client/1.2 (DNSGuard)",
            "Accept": "application/json",
        }
        if json_body:
            hdrs["Content-Type"] = "application/json"
        if self.token:
            hdrs["Authorization"] = self.token
        return hdrs

    def poll(self, timeout: float = 3.8) -> List[InteractshInteraction]:
        """Fetch and locally decrypt all queued interactions from the OAST server."""
        if self._closed:
            return []
        base = f"{self.scheme}://{self.server}" if "://" not in self.server else self.server
        url = f"{base.rstrip('/')}/poll?id={self.correlation_id}&secret={self.secret_key}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        raw_body = _open_url_resilient(req, timeout=timeout)
        payload = json.loads(raw_body.decode("utf-8", errors="replace"))
        if not isinstance(payload, dict):
            return []

        interactions: List[InteractshInteraction] = []
        data_list = payload.get("data") or []
        aes_key_b64 = payload.get("aes_key") or ""

        if data_list and aes_key_b64:
            enc_aes_key = base64.b64decode(aes_key_b64)
            aes_key = self.keypair.decrypt_oaep_sha256(enc_aes_key)
            for item_b64 in data_list:
                try:
                    blob = base64.b64decode(item_b64)
                    if len(blob) <= 16:
                        continue
                    iv = blob[:16]
                    ct = blob[16:]
                    # Modern Interactsh servers use AES-256-CTR; legacy versions use AES-256-CFB128.
                    plain_bytes = aes_ctr_decrypt(aes_key, iv, ct)
                    plain_str = plain_bytes.decode("utf-8", errors="replace").strip("\x00\r\n ")
                    parsed = _parse_interaction_json(plain_str, self.correlation_id, self._uid_tags)
                    if parsed is None:
                        plain_cfb = aes_cfb128_decrypt(aes_key, iv, ct)
                        plain_str_cfb = plain_cfb.decode("utf-8", errors="replace").strip("\x00\r\n ")
                        parsed = _parse_interaction_json(plain_str_cfb, self.correlation_id, self._uid_tags)
                    if parsed:
                        interactions.append(parsed)
                except Exception:
                    continue

        for extra_item in payload.get("extra") or []:
            if isinstance(extra_item, str):
                parsed = _parse_interaction_json(extra_item, self.correlation_id, self._uid_tags)
                if parsed:
                    interactions.append(parsed)

        return interactions

    def deregister(self, timeout: float = 1.8) -> bool:
        """Explicitly purge session and encrypted logs from the OAST server."""
        if self._closed:
            return True
        self._closed = True
        base = f"{self.scheme}://{self.server}" if "://" not in self.server else self.server
        url = f"{base.rstrip('/')}/deregister"
        body = json.dumps(
            {
                "correlation-id": self.correlation_id,
                "secret-key": self.secret_key,
            }
        ).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=self._headers(json_body=True), method="POST")
        try:
            _open_url_resilient(req, timeout=timeout)
            return True
        except Exception:
            return False

    def close_async(self) -> None:
        """Deregister asynchronously on a daemon thread to add zero user-facing latency."""
        if self._closed:
            return
        threading.Thread(target=self.deregister, daemon=True).start()


def register_oast_server(
    server: str,
    keypair: RSAKeyPair,
    token: Optional[str] = None,
    timeout: float = 4.5,
) -> InteractshSession:
    """Register a new session against a specific Interactsh server."""
    if "://" in server:
        scheme, host = server.split("://", 1)
        host = host.strip("/")
    else:
        scheme, host = "https", server.strip("/")

    cid = generate_xid()
    secret = str(uuid.uuid4())
    pub_b64 = base64.b64encode(keypair.public_key_pem()).decode("ascii")

    body = json.dumps(
        {
            "public-key": pub_b64,
            "secret-key": secret,
            "correlation-id": cid,
        }
    ).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Interactsh-Client/1.2 (DNSGuard)",
    }
    if token:
        headers["Authorization"] = token

    url = f"{scheme}://{host}/register"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    t0 = time.perf_counter()
    raw = _open_url_resilient(req, timeout=timeout)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    resp_obj = json.loads(raw.decode("utf-8", errors="replace"))
    msg = str(resp_obj.get("message", "")).lower()
    if "registration successful" not in msg and "success" not in msg:
        raise RuntimeError(f"Unexpected register response from {host}: {resp_obj}")

    return InteractshSession(
        server=host,
        correlation_id=cid,
        secret_key=secret,
        keypair=keypair,
        token=token,
        register_latency_ms=elapsed_ms,
        scheme=scheme,
    )


def register_fastest_oast_session(
    custom_server: Optional[str] = None,
    token: Optional[str] = None,
    servers: Tuple[str, ...] = DEFAULT_OAST_SERVERS,
    timeout: float = 4.5,
) -> Optional[InteractshSession]:
    """
    Generate a single RSA-2048 keypair and race multiple OAST servers concurrently,
    immediately returning the lowest-latency session without waiting on stragglers.
    """
    env_srv = custom_server or os.environ.get("DNSCHECK_OAST_SERVER")
    env_tok = token or os.environ.get("DNSCHECK_OAST_TOKEN")

    keypair = generate_rsa_keypair(bits=2048)

    if env_srv:
        candidates = [s.strip() for s in env_srv.split(",") if s.strip()]
    else:
        pool_list = list(servers)
        random.shuffle(pool_list)
        # Race 4 distinct public servers concurrently for minimum RTT & high availability
        candidates = pool_list[:4]

    winner_lock = threading.Lock()
    winner_event = threading.Event()
    winner_holder: List[InteractshSession] = []
    finished_count = 0
    total = len(candidates)

    def _try_candidate(srv: str) -> None:
        nonlocal finished_count
        sess: Optional[InteractshSession] = None
        try:
            sess = register_oast_server(srv, keypair=keypair, token=env_tok, timeout=timeout)
        except Exception:
            sess = None

        with winner_lock:
            finished_count += 1
            if sess is not None and not winner_holder:
                winner_holder.append(sess)
                winner_event.set()
                return
            if finished_count >= total:
                winner_event.set()

        # If another server already won the race, silently clean up this runner-up session
        if sess is not None:
            sess.close_async()

    pool = ThreadPoolExecutor(max_workers=max(1, len(candidates)))
    try:
        for srv in candidates:
            pool.submit(_try_candidate, srv)
        winner_event.wait(timeout=timeout + 2.5)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return winner_holder[0] if winner_holder else None
