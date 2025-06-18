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

crlPublisher = CRLPublisher(PRIVATE_KEY, CONTRACT_ADDRESS)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def publish_crl():
    crlPublisher.publish_crl()
    logger.info(f"New CRL published at {datetime.now()}")

if __name__ == '__main__':

    if INITIAL_PUBLISH == '1':
        publish_crl()

    scheduler = BlockingScheduler()
    scheduler.add_job(publish_crl, 'cron', hour=0, minute=0)

    ("Scheduler starting - will run daily at midnight")
    scheduler.start()