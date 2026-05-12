"""Dev-only X.509 CA + leaf cert minting.

Persists the CA key + cert to disk so multiple installer runs share one trust
anchor. Each redemption generates a fresh leaf keypair and signs it.
"""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class PemBundle:
    cert: str
    key:  str


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def load_or_mint_ca(ca_dir: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Load an existing dev CA from `ca_dir`, or mint a fresh one if absent."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    cert_path = ca_dir / "ca.cert.pem"
    key_path  = ca_dir / "ca.key.pem"

    if cert_path.exists() and key_path.exists():
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key  = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return key, cert  # type: ignore[return-value]

    key = _ec_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Skema dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, "skema-dev-ca"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=1))
        .not_valid_after(_now() + dt.timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256()))

    cert_path.write_text(_cert_pem(cert))
    key_path.write_text(_key_pem(key))
    os.chmod(key_path, 0o600)
    return key, cert


def mint_operator_cert(ca_key: ec.EllipticCurvePrivateKey,
                       ca_cert: x509.Certificate,
                       *,
                       operator_uuid: str,
                       hardware_fingerprint: str,
                       valid_days: int = 365) -> PemBundle:
    """Mint a fresh operator client cert signed by the dev CA.

    The fingerprint is embedded in the SAN as a URI for trace/audit; production
    can match the same pattern.
    """
    key = _ec_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"operator:{operator_uuid}"),
    ])
    san = x509.SubjectAlternativeName([
        x509.UniformResourceIdentifier(f"urn:skema:operator:{operator_uuid}"),
        x509.UniformResourceIdentifier(f"urn:skema:fingerprint:{hardware_fingerprint}"),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=1))
        .not_valid_after(_now() + dt.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                        critical=False)
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256()))
    return PemBundle(cert=_cert_pem(cert), key=_key_pem(key))


def ca_cert_pem(cert: x509.Certificate) -> str:
    return _cert_pem(cert)


def mint_server_cert(ca_key: ec.EllipticCurvePrivateKey,
                     ca_cert: x509.Certificate,
                     *,
                     common_name: str,
                     san_hosts: list[str] | None = None,
                     valid_days: int = 365) -> PemBundle:
    """Sign a SERVER_AUTH cert for the mock skema container in tests."""
    import ipaddress as _ip
    key = _ec_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    san_entries: list[x509.GeneralName] = []
    for h in (san_hosts or [common_name]):
        try:
            san_entries.append(x509.IPAddress(_ip.ip_address(h)))
        except ValueError:
            san_entries.append(x509.DNSName(h))
    san = x509.SubjectAlternativeName(san_entries)

    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=1))
        .not_valid_after(_now() + dt.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                        critical=False)
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256()))
    return PemBundle(cert=_cert_pem(cert), key=_key_pem(key))
