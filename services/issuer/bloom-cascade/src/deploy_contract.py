#!/usr/bin/env python3
"""
Deploy the simplified CRL Registry contract
"""

import os
import json
import time
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv
import logging

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


CONTRACT_PATH = os.getenv("CONTRACT_PATH")
ABI_FILE_PATH= os.getenv("ABI_FILE_PATH")


def read_contract(contract_file_path):
        """Read contract source from file"""
        try:
            with open(contract_file_path, 'r', encoding='utf-8') as file:
                contract_source = file.read()
            logger.info(f" Contract loaded from {contract_file_path}")
            return contract_source
        except FileNotFoundError:
            logger.info(f" Contract file not found: {contract_file_path}")
            return None
        except Exception as e:
            logger.info(f" Error reading contract: {e}")
            return None

def deploy_crl_contract(private_key):
    """Deploy the simplified CRL Registry contract"""

    rpc_url = os.getenv("RPC_URL", "https://ethereum-holesky-rpc.publicnode.com")
    
    if not private_key:
        private_key = input("Enter your private key (0x...): ")
    
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    account = Account.from_key(private_key)
    address = account.address
    
    logger.info(f" Deploying Simplified CRL Registry Contract")
    logger.info(f" Deployer Address: {address}")
    logger.info(f" Network: Holesky Testnet")
    logger.info(f" Balance: {w3.from_wei(w3.eth.get_balance(address), 'ether'):.6f} ETH")
    
    contract_source = read_contract(CONTRACT_PATH)
    
    logger.info(f" Compiling simplified contract...")
    
    try:
        from solcx import compile_source, install_solc, set_solc_version, get_installed_solc_versions
        
        req_version = '0.8.30'

        try:
            installed_versions = get_installed_solc_versions()
            
            if req_version in installed_versions:
                logger.info(f"Solc {req_version} already installed")
                set_solc_version(req_version)
                logger.info(f"Sol compiler version set to {req_version}")
            else:
                logger.info(f"Required sol compiler version {req_version} not installed. Installing...")
                install_solc(req_version)
                logger.info(f"Installed sol compiler version {req_version}")
                
                # IMPORTANT: Set the version after installation
                set_solc_version(req_version)
                logger.info(f"Sol compiler version set to {req_version}")
                
        except Exception as e:
            logger.error(f"Failed to setup Solc: {e}")
            return None
    
        compiled_sol = compile_source(contract_source, output_values=['abi', 'bin'])
        contract_id, contract_interface = compiled_sol.popitem()
        logger.info(f"Contract compiled successfully")
    
    except Exception as e:
        logger.info(f"Compilation failed: {e}")
        return None
        
    # Deploy contract
    logger.info(f"   Deploying contract...")
    
    try:
        contract = w3.eth.contract(
            abi=contract_interface['abi'],
            bytecode=contract_interface['bin']
        )
        
        gas_estimate = contract.constructor().estimate_gas()
        gas_limit = int(gas_estimate * 1.2)
        gas_price = w3.eth.gas_price
        
        logger.info(f"   Transaction details:")
        logger.info(f"   Gas estimate: {gas_estimate:,}")
        logger.info(f"   Gas limit: {gas_limit:,}")
        logger.info(f"   Estimated cost: {w3.from_wei(gas_limit * gas_price, 'ether'):.6f} ETH")
        
        transaction = contract.constructor().build_transaction({
            'from': address,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': w3.eth.get_transaction_count(address)
        })
        
        signed_txn = account.sign_transaction(transaction)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        logger.info(f" Transaction sent: {tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        
        if receipt.status == 1:
            contract_address = receipt.contractAddress
            gas_used = receipt.gasUsed
            actual_cost = w3.from_wei(gas_used * gas_price, 'ether')
            
            logger.info(f"  Contract deployed successfully!")
            logger.info(f"  Contract address: {contract_address}")
            logger.info(f"  Gas used: {gas_used:,}")
            logger.info(f"  Cost: {actual_cost:.6f} ETH")
            logger.info(f"  Etherscan: https://holesky.etherscan.io/address/{contract_address}")
            
            # Test contract
            deployed_contract = w3.eth.contract(
                address=contract_address,
                abi=contract_interface['abi']
            )
            
            name = deployed_contract.functions.NAME().call()
            version = deployed_contract.functions.VERSION().call()
            
            logger.info(f"  Contract test successful:")
            logger.info(f"  Name: {name}")
            logger.info(f"  Version: {version}")
            
            # Save deployment info
            deployment_info = {
                "contract_address": contract_address,
                "contract_abi": contract_interface['abi'],
                "transaction_hash": tx_hash.hex(),
                "deployer_address": address,
                "network": "holesky",
                "gas_used": gas_used,
                "deployment_cost_eth": float(actual_cost),
                "deployed_at": int(time.time()),
                "deployed_at_readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            }
            
            with open(ABI_FILE_PATH, 'w') as f:
                json.dump(deployment_info, f, indent=2)
            
            logger.info(f" Deployment info saved to: {ABI_FILE_PATH}.json")
            
            # Show DID method usage
            logger.info(f"\n Your Custom DID Method:")
            logger.info(f"   Method Name: crl")
            logger.info(f"   Network: holesky") 
            logger.info(f"   Your DID: {address.lower()}")
            logger.info(f"   Contract: {contract_address}")
            
            return deployment_info
            
        else:
            logger.info(f" Transaction failed")
            return None
            
    except Exception as e:
        logger.info(f" Deployment failed: {e}")
        return None