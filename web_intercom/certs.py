"""Self-signed certificate helpers for LAN HTTPS demos."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def local_ipv4_addresses() -> list[str]:
    addresses = {"127.0.0.1"}
    hostname = socket.gethostname()
    try:
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            address = item[4][0]
            if not address.startswith("169.254."):
                addresses.add(address)
    except socket.gaierror:
        pass

    # UDP connect does not send packets; it asks the OS which local address
    # would be used for outbound LAN traffic.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        addresses.add(sock.getsockname()[0])
    except OSError:
        pass
    finally:
        sock.close()
    return sorted(addresses)


def ensure_self_signed_cert(cert_dir: Path, hosts: list[str]) -> tuple[Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    _chmod_best_effort(cert_dir, 0o700)
    cert_path = cert_dir / "web_intercom.crt"
    key_path = cert_dir / "web_intercom.key"
    if cert_path.exists() and key_path.exists():
        _chmod_best_effort(key_path, 0o600)
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Web Intercom"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Secure Web Intercom LAN Certificate"),
        ]
    )

    san_entries: list[x509.GeneralName] = [x509.DNSName("localhost")]
    for host in hosts:
        if not host:
            continue
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san_entries.append(x509.DNSName(host))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private_key(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )
    return cert_path, key_path


def _write_private_key(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
    finally:
        if fd != -1:
            os.close(fd)
    _chmod_best_effort(path, 0o600)


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass
