# Implementation of RSA functions

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_rsa_keypair():
    """Generates a private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# SERIALIZATION

def serialize_private_key(private_key, password_bytes):
    """
    Serializes a private key to PEM format, encrypting it with a password.
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )
    return pem.decode('utf-8') # Store as a string in JSON

def serialize_public_key(public_key):
    """
    Serializes a public key to PEM format.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8') # Store as a string in JSON



def load_private_key(pem_string, password_bytes):
    """
    Loads a serialized and encrypted private key.
    """
    private_key = serialization.load_pem_private_key(
        pem_string.encode('utf-8'),
        password=password_bytes
    )
    return private_key

def load_public_key(pem_string):
    public_key = serialization.load_pem_public_key(
        pem_string.encode('utf-8')
    )
    return public_key

# signing

def sign_data(private_key, data_bytes):
    """
    Signs data using the private key.
    """
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex() # Return as hex string for JSON

def verify_signature(public_key, data_bytes, signature_hex):
    try:
        signature = bytes.fromhex(signature_hex)
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        # InvalidSignature
        return False

# Certificate function

def generate_csr(private_key, username):
    """
    Generates a Certificate Signing Request (CSR)
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Leganes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Wende & Kevin"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    # Generate the CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256())
    
    return csr

def serialize_csr_to_pem(csr):
    """Serializes a CSR object to PEM format."""
    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def load_certificate_from_pem_file(filepath):
    """
    Loads an X.509 certificate from a PEM file.
    """
    with open(filepath, "rb") as cert_file:
        return x509.load_pem_x509_certificate(cert_file.read())

def load_certificate_from_pem_string(pem_string):
    """
    Loads an X.509 certificate from a PEM string.
    """
    return x509.load_pem_x509_certificate(pem_string.encode('utf-8'))

def verify_certificate_signature(cert_to_verify, issuer_public_key):
    """
    Verifies that a certificate was correctly signed by the issuer.
    """
    try:
        # PKCS1v15 as you've told us int he guide
        padding_algo = asym_padding.PKCS1v15()
        issuer_public_key.verify(
            signature=cert_to_verify.signature,
            data=cert_to_verify.tbs_certificate_bytes,
            padding=padding_algo,
            algorithm=cert_to_verify.signature_hash_algorithm
        )
        return True
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False


