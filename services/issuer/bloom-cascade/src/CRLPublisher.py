import os
import json
import time
import base64
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
import requests
import redis
import logging
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from PyKCS11 import PyKCS11  # For NetSafe eToken interaction

from cascade import Cascade

load_dotenv()

RPC_URL = os.getenv("RPC_URL")
ABI_FILE_PATH = os.getenv("ABI_FILE_PATH")

API_KEY = os.getenv("PINATA_API_KEY")
API_SECRET = os.getenv("PINATA_SECRET_KEY")

IPFS_PINNING_ENDPOINT = os.getenv("IPFS_PINNING_ENDPOINT")

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

# NetSafe eToken configuration
PKCS11_LIB_PATH = os.getenv("PKCS11_LIB_PATH", '/usr/lib/libeToken.so')  # Path to NetSafe PKCS#11 library
TOKEN_PIN = os.getenv("TOKEN_PIN")
CERT_LABEL = os.getenv("CERT_LABEL", "IssuerECKey")  # Certificate label on token
KEY_LABEL = os.getenv("KEY_LABEL", "Private Key")    # Private key label on token

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CRLPublisher:
    def __init__(self, private_key, contract_address):
        try:
            with open(ABI_FILE_PATH, "r") as file:
                self.abi = json.load(file)

            self.account = Account.from_key(private_key)
            self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
            self.contract = self.w3.eth.contract(address=contract_address, abi=self.abi)
            self.pinata_api_key = API_KEY
            self.pinata_secret = API_SECRET

            self.R = set()  # valid creds
            self.S = set()  # invalid creds
            self.cascade = Cascade()
            
            self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            self.redis.ping()
            logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
            
            # Initialize PKCS#11 for NetSafe eToken
            self.pkcs11 = PyKCS11.PyKCS11Lib()
            self.pkcs11.load(PKCS11_LIB_PATH)
            self.session = None
            self._initialize_token()
        
        except FileNotFoundError as e:
            logger.error(f"ABI file not found: {e}")
            raise
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
        except redis.AuthenticationError as e:
            logger.error(f"Redis authentication failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize NetSafe eToken: {e}")
            raise

    def debug_token_contents(self):
        """Debug method to list all objects on the token"""
        try:
            logger.info("=== Token Contents Debug ===")
            
            # List all certificates
            cert_objects = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
            logger.info(f"Found {len(cert_objects)} certificate(s):")
            for i, cert_obj in enumerate(cert_objects):
                try:
                    attrs = self.session.getAttributeValue(cert_obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_ID])
                    label = attrs[0] if attrs[0] else "No label"
                    cert_id = attrs[1] if attrs[1] else "No ID"
                    logger.info(f"  Cert {i}: Label='{label}', ID={cert_id}")
                except:
                    logger.info(f"  Cert {i}: Could not read attributes")
            
            # List all private keys
            key_objects = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            logger.info(f"Found {len(key_objects)} private key(s):")
            for i, key_obj in enumerate(key_objects):
                try:
                    attrs = self.session.getAttributeValue(key_obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_ID, PyKCS11.CKA_KEY_TYPE])
                    label = attrs[0] if attrs[0] else "No label"
                    key_id = attrs[1] if attrs[1] else "No ID"
                    if attrs[2] == PyKCS11.CKK_RSA:
                        key_type = "RSA"
                    elif attrs[2] == PyKCS11.CKK_ECDSA:
                        key_type = "ECDSA"
                    elif attrs[2] == PyKCS11.CKK_EC:
                        key_type = "EC"
                    else:
                        key_type = f"Type {attrs[2]}"
                    logger.info(f"  Key {i}: Label='{label}', ID={key_id}, Type={key_type}")
                except:
                    logger.info(f"  Key {i}: Could not read attributes")
            
            logger.info("=== End Token Debug ===")
                    
        except Exception as e:
            logger.error(f"Error debugging token contents: {e}")

    def test_token_signing(self):
        """Test method to verify token signing works"""
        try:
            logger.info("Testing token signing capability...")
            test_data = b"test signing data"
            signature = self._sign_with_token(test_data)
            logger.info(f"Successfully signed test data. Signature length: {len(signature)} bytes")
            return True
        except Exception as e:
            logger.error(f"Token signing test failed: {e}")
            return False

    def _initialize_token(self):
        """Initialize connection to NetSafe eToken"""
        try:
            slots = self.pkcs11.getSlotList(tokenPresent=True)
            if not slots:
                raise Exception("No tokens found")
            
            slot = slots[0]  # Use first available slot
            self.session = self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
            self.session.login(TOKEN_PIN)
            logger.info("Successfully connected to NetSafe eToken")
            
        except Exception as e:
            logger.error(f"Failed to initialize token: {e}")
            raise

    def _get_certificate_chain(self):
        """Retrieve certificate chain from NetSafe eToken"""
        try:
            # Try to find certificate by label first
            cert_objects = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
            
            if CERT_LABEL:
                # Filter by label if specified
                labeled_certs = []
                for cert_obj in cert_objects:
                    try:
                        label = self.session.getAttributeValue(cert_obj, [PyKCS11.CKA_LABEL])[0]
                        if label and CERT_LABEL in str(label):
                            labeled_certs.append(cert_obj)
                    except:
                        continue
                if labeled_certs:
                    cert_objects = labeled_certs
            
            if not cert_objects:
                raise Exception("No certificates found on token")
            
            # Use first certificate found
            cert_obj = cert_objects[0]
            
            # Get certificate value and ID for key matching
            cert_attrs = self.session.getAttributeValue(cert_obj, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
            cert_der = bytes(cert_attrs[0])
            self.cert_id = cert_attrs[1] if cert_attrs[1] else None
            
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_der)
            
            # For now, return single certificate - extend this to build full chain
            cert_chain = [base64.b64encode(cert_der).decode('utf-8')]
            
            logger.info("Retrieved certificate chain from token")
            return cert_chain
            
        except Exception as e:
            logger.error(f"Failed to get certificate chain: {e}")
            raise

    def _find_private_key(self):
        """Find private key on token using multiple methods"""
        try:
            # Method 1: Try to find by CKA_ID matching the certificate
            if hasattr(self, 'cert_id') and self.cert_id:
                key_objects = self.session.findObjects([
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_ID, self.cert_id)
                ])
                if key_objects:
                    logger.info("Found private key by matching certificate ID")
                    return key_objects[0]
            
            # Method 2: Try to find by label if specified
            if KEY_LABEL:
                key_objects = self.session.findObjects([
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_LABEL, KEY_LABEL)
                ])
                if key_objects:
                    logger.info("Found private key by label")
                    return key_objects[0]
            
            # Method 3: Find any EC private key (try both ECDSA and EC types)
            for key_type in [PyKCS11.CKK_ECDSA, PyKCS11.CKK_EC]:
                key_objects = self.session.findObjects([
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_KEY_TYPE, key_type)
                ])
                if key_objects:
                    key_type_name = "ECDSA" if key_type == PyKCS11.CKK_ECDSA else "EC"
                    logger.info(f"Found {key_type_name} private key")
                    return key_objects[0]
            
            # Method 4: Find any private key
            key_objects = self.session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)
            ])
            if key_objects:
                logger.info("Found private key (generic search)")
                return key_objects[0]
            
            raise Exception("No private keys found on token")
            
        except Exception as e:
            logger.error(f"Failed to find private key: {e}")
            raise

    def _sign_with_token(self, data):
        """Sign data using NetSafe eToken EC private key"""
        try:
            # Find private key object
            private_key = self._find_private_key()
            
            # Try ECDSA with SHA-256 first
            try:
                signature = self.session.sign(private_key, data, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256))
                return bytes(signature)
            except:
                logger.info("CKM_ECDSA_SHA256 not supported, trying CKM_ECDSA with manual hashing")
                
                # Fallback: Hash data manually and use CKM_ECDSA
                import hashlib
                hashed_data = hashlib.sha256(data).digest()
                signature = self.session.sign(private_key, hashed_data, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA))
                return bytes(signature)
            
        except Exception as e:
            logger.error(f"Failed to sign with token: {e}")
            raise

    def _create_signed_jwt(self, cascade_data):
        """Create and sign JWT containing base64-encoded cascade data"""
        try:
            # Base64 encode the cascade data
            cascade_b64 = base64.b64encode(cascade_data).decode('utf-8')
            
            # Get certificate chain
            cert_chain = self._get_certificate_chain()
            
            # Create JWT payload
            payload = {
                'iss': 'CRL-Publisher',
                'iat': int(time.time()),
                'exp': int(time.time()) + 86400,  # Expires in 24 hours
                'cascade': cascade_b64,
                'version': 1
            }
            
            # Create JWT header with certificate chain
            header = {
                'alg': 'ES256',  # ECDSA with SHA-256
                'typ': 'JWT',
                'x5c': cert_chain  # Certificate chain in header
            }
            
            # Manually create JWT since we need to sign with eToken
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Create signing input
            signing_input = f"{header_b64}.{payload_b64}".encode()
            
            # Sign with eToken
            signature = self._sign_with_token(signing_input)
            signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            
            # Construct final JWT
            jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
            
            logger.info("Successfully created and signed JWT with NetSafe eToken (ECDSA)")
            return jwt_token
            
        except Exception as e:
            logger.error(f"Failed to create signed JWT: {e}")
            raise

    def _get_all_credentials(self):
        try:
            for key in self.redis.scan_iter(match='*[0-9]*'):
                try:
                    credential_id = key
                    status = self.redis.get(key)
                    if status == 'true':
                        self.S.add(credential_id)  # add to invalid
                    elif status == 'false':
                        self.R.add(credential_id)  # add to valid
                except (ValueError, TypeError):
                    continue
                    
        except Exception as e:
            print(f"Error: {e}")

    def publish_crl(self):
        try:
            self._get_all_credentials()
            
            # Build the cascade
            self.cascade.build_cascade(self.R, self.S)
            
            # Serialize the cascade
            cascade_blob = self.cascade.serialize_cascade()
            
            # Create signed JWT with cascade data
            jwt_token = self._create_signed_jwt(cascade_blob)
            
            # Upload JWT to IPFS
            ipfs_hash = self.upload_to_ipfs(jwt_token.encode())

            transaction = self.contract.functions.publishCRL(
                ipfs_hash,
                24
            ).build_transaction({
                'from': self.account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address)
            })
            
            signed_txn = self.account.sign_transaction(transaction)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            
            logger.debug(f"Transaction: {tx_hash.hex()}")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                logger.debug("CRL published successfully!")
                
                # Parse events
                events = self.contract.events.CRLPublished().process_receipt(receipt)
                if events:
                    event = events[0]
                    logger.info(f"   Event: CRL Published")
                    logger.info(f"   IPFS Hash: {event['args']['ipfsHash']}")
                    logger.info(f"   Version: {event['args']['version']}")
                    logger.info(f"   Expires: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(event['args']['expiresAt']))}")
                    logger.info(f"   JWT signed with NetSafe eToken (ECDSA)")
            else:
                logger.error("Transaction failed")
                return False
                
        except Exception as e:
            logger.error(f"Failed to publish CRL: {e}")
            return False
        finally:
            self._cleanup_token()
    
    def getCRL(self):
        return self.contract.functions.getCRL("0xC887f232c81c4609CF98857c6Fe55FDE8d24f418").call()

    def upload_to_ipfs(self, data):
        """Upload JWT data to IPFS"""
        headers = {
            'pinata_api_key': self.pinata_api_key,
            'pinata_secret_api_key': self.pinata_secret
        }
        
        response = requests.post(
            IPFS_PINNING_ENDPOINT,
            headers=headers,
            files={'file': data}
        )
        
        return response.json()['IpfsHash']
    
    def _cleanup_token(self):
        """Clean up eToken session"""
        try:
            if self.session:
                self.session.logout()
                self.session.closeSession()
                logger.info("NetSafe eToken session closed")
        except Exception as e:
            logger.warning(f"Error cleaning up token session: {e}")

    def __del__(self):
        """Destructor to ensure token session is cleaned up"""
        self._cleanup_token()