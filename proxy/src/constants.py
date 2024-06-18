import os
from dotenv import load_dotenv

load_dotenv()

CONFIG_PATH = os.getenv('CONFIG_PATH')
LOG_PATH = os.getenv('LOG_PATH')
MODULES_PATH = os.getenv('MODULES_PATH')
CERTIFICATES_PATH = os.getenv('CERTIFICATES_PATH')
LOG_REFRESH_TIME = int(os.getenv('LOG_REFRESH_TIME'))
DB_URL = os.getenv('DB_URL')