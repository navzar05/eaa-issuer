from cascade import Cascade

from apscheduler.schedulers.blocking import BlockingScheduler

from web3 import Web3, HTTPProvider
from eth_abi import abi

import logging
import requests
import json

import os
from dotenv import load_dotenv
# Load environment variables from .env file
load_dotenv(dotenv_path="./src/.env_local")

# Access environment variables
STATE_LIST_FILENAME = os.getenv("STATE_LIST_FILENAME")
LOGGING_FILENAME = os.getenv("LOGGING_FILENAME")
BLOBLSCAN_URL_TX = os.getenv("BLOBLSCAN_URL_TX")
BLOBLSCAN_URL_BLOBS = os.getenv("BLOBLSCAN_URL_BLOBS")
RPC_URL = os.getenv("RPC_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
ETHERSCAN_API_URL = os.getenv("ETHERSCAN_API_URL")

print(f"State list file: {STATE_LIST_FILENAME}")

R = set() # Valid creds
S = set() # Revoked creds
r_hat = 50 # TODO genreaza-l pe baza formulei din articol

logger = logging.getLogger(__name__)

def read_state_list():

    with open(STATE_LIST_FILENAME) as f:
        id_status_list = [line.strip() for line in f if line.strip()]

    for item in id_status_list:
        hex_hash, status = item.split(':')
        if status == '1':
            R.add(hex_hash)
        else:
            S.add(hex_hash)

def publish_blob(cascade):
    w3 = Web3(HTTPProvider(RPC_URL))
    BLOB_DATA = cascade.serialize_cascade()
    # print(f"Blob data size: {len(BLOB_DATA)} bytes")
    if len(BLOB_DATA) != 131072:
        raise ValueError(f"Blob data size is {len(BLOB_DATA)}, expected 131072 bytes")

    # # encode some data
    # text = "<( o.O )>"
    # encoded_text = abi.encode(["string"], [text])

    # # subtract the length of the encoded text divided into 32-byte chunks from 4096 and pad the rest with zeros
    # padding_bytes = (b"\x00" * 32 * (4096 - len(encoded_text) // 32))

    # BLOB_DATA = padding_bytes + encoded_text
    # print(f"Blob data size: {len(BLOB_DATA)} bytes")

    acct = w3.eth.account.from_key(PRIVATE_KEY)

    tx = {
    "type": 3,
    "chainId": 17000, # 17000 Holeksy
    "from": acct.address,
    "to": "0x0000000000000000000000000000000000000000",
    "value": 0,
    "maxFeePerGas": 10**10,
    "maxPriorityFeePerGas": 10**10,
    "maxFeePerBlobGas": 10**10,
    "nonce": w3.eth.get_transaction_count(acct.address),
    "gas": 21000, # TODO: de estimat pe viitor
    "data": ""
    }

    # tx["gas"] = w3.eth.estimate_gas(tx)
    signed = acct.sign_transaction(tx, blobs=[BLOB_DATA])
    # signed["gas"] = w3.eth.estimate_gas(signed)
        
    
    logger.info(f"Signed Transaction Hash: {signed.hash.hex()}")

    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    logger.info(f"Transaction Hash: {tx_hash.hex()}")

    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    logger.info(f"Transaction Receipt: {tx_receipt}")


def get_block_transactions(tx_hash):
    w3 = Web3(HTTPProvider(RPC_URL))
    tx = w3.eth.get_transaction(tx_hash)
    blob_versioned_hashes = tx.get('blobVersionedHashes', [])

    if not blob_versioned_hashes:
        print("No blob hashes found in this transaction")
        exit()

    # Use the eth_getBlobsByHash method to get the blob data
    # Note: This is a custom RPC method for EIP-4844
    blob_data = w3.provider.make_request(
        "eth_getBlobsByHash",
        [blob_versioned_hashes]
    )

    # Print the result
    print(json.dumps(blob_data, indent=2))

    # If the result contains the blob data, you can process it
    if "result" in blob_data and blob_data["result"]:
        # Process blob data here
        for blob in blob_data["result"]:
            # Decode the blob data as needed
            decoded_data = bytes.fromhex(blob[2:])  # Remove '0x' prefix
            print(f"Blob size: {len(decoded_data)} bytes")


def get_blob_data(tx_hash):
    params = {
        "module": "proxy",
        "action": "eth_getTransactionByHash",
        "txhash": tx_hash,
        "apikey": ETHERSCAN_API_KEY
    }
    
    response = requests.get(ETHERSCAN_API_URL, params=params)
    tx_data = json.loads(response.text)
    
    if "result" not in tx_data or tx_data["result"] is None:
        print(f"Transaction not found: {tx_hash}")
        return None
    
    # Check if this is a blob transaction (has blobVersionedHashes)
    if "blobVersionedHashes" not in tx_data["result"] or not tx_data["result"]["blobVersionedHashes"]:
        print(f"Transaction {tx_hash} does not contain blobs")
        return None
    
    # Get the blob data using the eth_getBlobsByHash RPC method
    blob_hashes = tx_data["result"]["blobVersionedHashes"]
    
    blob_params = {
        "module": "proxy",
        "action": "engine_getBlobsV1",
        "blobVersionedHashes": blob_hashes,
        "apikey": ETHERSCAN_API_KEY
    }
    
    blob_response = requests.get(ETHERSCAN_API_URL, params=blob_params)
    blob_data = json.loads(blob_response.text)
    
    return blob_data


def post_crl():
    
    read_state_list()

    csd = Cascade(R, S, r_hat)
    publish_blob(csd)

        


if __name__ == '__main__':

    logging.basicConfig(filename=LOGGING_FILENAME, level=logging.INFO)

    # # init post
    post_crl()

    scheduler = BlockingScheduler()
    scheduler.add_job(post_crl, 'interval', seconds=30)

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped.")

       