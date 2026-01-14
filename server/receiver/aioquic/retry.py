import binascii
import ipaddress
import struct
import time
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..buffer import Buffer
from ..tls import (
    CipherSuite,
    cipher_suite_hash,
    hkdf_expand_label,
    hkdf_extract,
    push_opaque,
)
from .connection import NetworkAddress
from .packet import QuicHeader

INITIAL_SALT_RETRY = binascii.unhexlify("1d76cd55946826b6db1067f90de53e37b1bdc98b")


def get_unix_timestamp_network_byte_order() -> bytes:
    """Get unix timestamp and convert to network byte order."""
    timestamp = time.time()
    timestamp_int = int(timestamp)
    network_byte_order = struct.pack(">Q", timestamp_int)
    return network_byte_order


def encode_address(addr: NetworkAddress) -> bytes:
    return ipaddress.ip_address(addr[0]).packed + bytes([addr[1] >> 8, addr[1] & 0xFF])


def derive_key_iv(cid: bytes) -> Tuple[bytes, bytes]:
    algorithm = cipher_suite_hash(CipherSuite.AES_128_GCM_SHA256)
    initial_secret = hkdf_extract(algorithm, INITIAL_SALT_RETRY, cid)
    secret = hkdf_expand_label(
        algorithm, initial_secret, b"retry token", b"", algorithm.digest_size
    )
    return (
        hkdf_expand_label(algorithm, secret, b"token key", b"", 16),
        hkdf_expand_label(algorithm, secret, b"token iv", b"", 12),
    )


class QuicRetryTokenHandler:
    def __init__(self) -> None: ...

    def create_token(
        self,
        addr: NetworkAddress,
        scid: bytes,
        original_destination_connection_id: bytes,
        retry_source_connection_id: bytes,
    ) -> bytes:
        # derive key and iv from connection ID
        key, iv = derive_key_iv(scid)
        nonce = bytearray(iv)
        timestamp = get_unix_timestamp_network_byte_order()
        for i in range(len(iv)):
            if i < 8:
                nonce[i] ^= timestamp[i]
            else:
                nonce[i] ^= 0
        nonce = bytes(nonce)

        # Serial data
        flag = len(original_destination_connection_id).to_bytes(
            1, byteorder="big", signed=False
        )
        # print(f"ordidl = {flag.hex()}")
        aad = flag + timestamp
        # print(f"AAD = {aad.hex()}")

        # buf = Buffer(capacity=512)
        # push_opaque(buf, 1, original_destination_connection_id)
        # print(f"odcid = {original_destination_connection_id.hex()}")
        # # push_opaque(buf, 1, retry_source_connection_id)
        # push_opaque(buf, 1, encode_address(addr))
        # push_opaque(buf, 1, encode_address(addr)[:2])
        # plaintext = buf.data
        plaintext = (
            original_destination_connection_id
            + encode_address(addr)
            + encode_address(addr)[:2]
        )
        # print(f"plaintext = {plaintext.hex()}")

        aead = AESGCM(key)
        try:
            ciphertext = aead.encrypt(nonce, plaintext, aad)
        except Exception as e:
            # print(f"fail to decrypt: {e}")
            raise ValueError(f"Failed to encrypt: {e}")
        # print(f"ciphertext = {ciphertext.hex()}")

        return aad + ciphertext

    def validate_token(
        self, addr: NetworkAddress, header: QuicHeader, token: bytes
    ) -> Tuple[bytes, bytes]:
        """Validate token.

        Token format {
            Token Type (1),
            Original Destination ID Length (7),
            Timestamp (64),
            --------Below are encrypted--------
            Original Destination ID (0..160),
            Source IP Address (32),
            Sourt Port (16)
            -----------------------------------
            Authentication Tag (128)
        }

        """
        TIMESTAMP_SIZE_IN_BYTES = 8
        # AUTH_TAG_SIZE_IN_BYTES = 16
        # AEAD_NONCE_SIZE = 12
        offset = 0
        if len(token) < 39:  # 1+8+8+4+2 + tag(16) = 39
            raise ValueError("Invalid token format")
        # parse the aad part of the token
        first_byte = token[offset]
        # token_type = int((first_byte & 0x80) >> 7)
        odidl = int(first_byte & 0x7F)
        # print(f"odidl = {odidl}")
        offset += 1
        timestamp = token[offset : offset + TIMESTAMP_SIZE_IN_BYTES]
        offset += TIMESTAMP_SIZE_IN_BYTES

        # derive key and iv from dcid
        cid = header.source_cid
        key, iv = derive_key_iv(cid)
        nonce = bytearray(iv)
        for i in range(len(iv)):
            if i < 8:
                nonce[i] ^= timestamp[i]
            else:
                nonce[i] ^= 0
        nonce = bytes(nonce)
        # print(f"Token = {token.hex()}")
        # print(f"Key = {key.hex()}")
        # print(f"Nonce = {nonce.hex()}")

        associated_data = token[:9]
        # print(f"AAD = {associated_data.hex()}")

        combined_data = token[9:]
        # print(f"ciphertext = {combined_data.hex()}")

        # create aead cipher
        aead = AESGCM(key)
        try:
            plaintext = aead.decrypt(nonce, combined_data, associated_data)
        except Exception as e:
            # print(f"fail to decrypt: {e}")
            raise ValueError(f"Failed to decrypt token: {e}")

        # print("decode success")
        # print(f"plaintext = {plaintext.hex()}")

        # buf = Buffer(data=plaintext)
        # original_destination_connection_id = pull_opaque(buf, odidl)
        offset = odidl
        original_destination_connection_id = plaintext[:offset]
        # print(f"odcid = {original_destination_connection_id.hex()}")
        # sip = pull_opaque(buf, 4)
        # sip = plaintext[offset:offset+4]
        # offset+=4
        # print(f"{sip.hex()}")
        # _sport = pull_opaque(buf, 2)
        # _sport = plaintext[offset:offset+2]
        # print(f"{_sport.hex()}")

        # if sip != encode_address(addr):
        #     print(f"Validation error, expect {encode_address(addr)} got {sip}")
        #     raise ValueError("Remote address does not match.")
        # else:
        #     print("Validation passed")

        return original_destination_connection_id, header.destination_cid
