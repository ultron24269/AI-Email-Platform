"""Generate a throw-away CA and leaf certificates for offline TLS tests."""
import datetime, ipaddress, os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def _name(cn, org=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)

def make_ca(outdir):
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name("Test Root CA", "TestCA"))
            .issuer_name(_name("Test Root CA", "TestCA")).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=400))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    with open(os.path.join(outdir, "ca.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert

def make_leaf(outdir, name, ca, sans, days_from=-30, days_to=60, self_signed=False):
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subj = _name(sans[0], "Leaf Org")
    issuer = subj if self_signed else ca[1].subject
    signer = key if self_signed else ca[0]
    san_list = []
    for s in sans:
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            san_list.append(x509.DNSName(s))
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now + datetime.timedelta(days=days_from))
         .not_valid_after(now + datetime.timedelta(days=days_to))
         .add_extension(x509.SubjectAlternativeName(san_list), critical=False))
    cert = b.sign(signer, hashes.SHA256())
    cpath, kpath = os.path.join(outdir, name + ".crt"), os.path.join(outdir, name + ".key")
    with open(cpath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cpath, kpath
