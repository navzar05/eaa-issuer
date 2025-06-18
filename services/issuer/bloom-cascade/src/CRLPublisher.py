import os
import json
import time
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
import requests
import redis
import logging

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

            self.R = set() # valid creds
            self.S = set() # invalid creds
            self.cascade = Cascade()
            
            self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, password=REDIS_PASSWORD)

            self.redis.ping()
            logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        
        except FileNotFoundError as e:
            logger.error(f"ABI file not found: {e}")

        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
        except redis.AuthenticationError as e:
            logger.error(f"Redis authentication failed: {e}")
            raise

    def _get_all_credentials(self):
        try:
                        
            for key in self.redis.scan_iter(match='*[0-9]*'):
                try:
                    credential_id = key
                    status = self.redis.get(key)
                    if status == 'true':
                        self.S.add(credential_id) # add to invalid
                    elif status == 'false':
                        self.R.add(credential_id) # add to valid
                except (ValueError, TypeError):
                    continue
                    
        except Exception as e:
            print(f"Error: {e}")

        
    def publish_crl(self):

        self._get_all_credentials()
        
        # build the cascade
        self.cascade.build_cascade(self.R, self.S)
        
        # serialize the cascade
        blob = self.cascade.serialize_cascade()
        
        ipfs_hash = self.upload_to_ipfs(blob)

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
        else:
            logger.error("Transaction failed")
            return False
    
    def getCRL(self):
        return self.contract.functions.getCRL("0xC887f232c81c4609CF98857c6Fe55FDE8d24f418").call()

    def upload_to_ipfs(self, data):
        """This is where IPFS API keys are actually used"""
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