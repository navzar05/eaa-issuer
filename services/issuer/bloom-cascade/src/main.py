from apscheduler.schedulers.blocking import BlockingScheduler
from datetime import datetime
from CRLPublisher import CRLPublisher
import os
from dotenv import load_dotenv
import logging
from datetime import datetime

load_dotenv()

CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
INITIAL_PUBLISH = os.getenv("INITIAL_PUBLISH")
USE_IPFS = os.getenv("USE_IPFS")
USE_BLOB = os.getenv("USE_BLOB")

crlPublisher = CRLPublisher(private_key=PRIVATE_KEY)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def publish_crl():
    if USE_IPFS == '1' and USE_BLOB == '1':
        crlPublisher.publish_crl()
        crlPublisher.publish_blob_crl()
    elif USE_IPFS == '1':
        crlPublisher.publish_crl()
    elif USE_BLOB == '1':
        crlPublisher.publish_blob_crl()
    else:
        crlPublisher.publish_blob_crl()

    

    logger.info(f"New CRL published at {datetime.now()}")

if __name__ == '__main__':

    if INITIAL_PUBLISH == '1':
        publish_crl()

    scheduler = BlockingScheduler()
    scheduler.add_job(publish_crl, 'cron', hour=0, minute=0)

    ("Scheduler starting - will run daily at midnight")
    scheduler.start()