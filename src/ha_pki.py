import hashlib
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def _write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _load_or_create_ca(root: Path):
    key_path = root / "ha-ca.key"
    cert_path = root / "ha-ca.pem"
    if key_path.exists() and cert_path.exists():
        try:
            key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if key.public_key().public_numbers() == cert.public_key().public_numbers():
                return key, cert
        except (OSError, TypeError, ValueError):
            pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, "LM DHCP HA root")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=None, decipher_only=None),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    _write(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
        0o600)
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    return key, cert


def issue_member_material(pki_dir: str, member_id: str, host: str) -> dict:
    """Issue one node-specific certificate from the persistent DHCP HA CA."""
    member_id = str(member_id or "").strip()
    host = str(host or "").strip()
    if not member_id or not host:
        raise ValueError("member id and host are required")

    root = Path(pki_dir)
    ca_key, ca_cert = _load_or_create_ca(root)
    safe_id = hashlib.sha256(member_id.encode("utf-8")).hexdigest()[:24]
    cert_path = root / f"{safe_id}.crt"
    key_path = root / f"{safe_id}.key"
    if cert_path.exists() and key_path.exists():
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None)
            names = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            try:
                expected = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                expected = x509.DNSName(host)
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            if (
                cert.issuer == ca_cert.subject
                and key.public_key().public_numbers()
                == cert.public_key().public_numbers()
                and expected in names
                and cert.not_valid_after_utc
                > datetime.now(timezone.utc) + timedelta(days=30)
            ):
                return {
                    "ha_ca_pem": ca_cert.public_bytes(
                        serialization.Encoding.PEM).decode("ascii"),
                    "ha_cert_pem": cert_path.read_text(encoding="ascii"),
                    "ha_key_pem": key_path.read_text(encoding="ascii"),
                }
        except (
            InvalidSignature, OSError, TypeError, ValueError,
            x509.ExtensionNotFound,
        ):
            pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, f"lm-dhcp-{safe_id}")])
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    _write(cert_path, cert_pem, 0o644)
    _write(key_path, key_pem, 0o600)
    return {
        "ha_ca_pem": ca_cert.public_bytes(
            serialization.Encoding.PEM).decode("ascii"),
        "ha_cert_pem": cert_pem.decode("ascii"),
        "ha_key_pem": key_pem.decode("ascii"),
    }
