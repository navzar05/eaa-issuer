import os

from CRLPublisher import CRLPublisher

from dotenv import load_dotenv

load_dotenv(dotenv_path='../.env')

crl = CRLPublisher(os.getenv('PRIVATE_KEY'))

response = crl.getCRL('0xC887f232c81c4609CF98857c6Fe55FDE8d24f418', saveMethod=0)

print(response)