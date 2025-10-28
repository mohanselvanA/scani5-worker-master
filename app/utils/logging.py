import logging


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cve_sync.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("scani5")