import os

QG_DB_URI = os.environ.get('QG_DB_URI') or 'mysql+pymysql://root:123456@localhost:3309/qualys_guard'
SWG_DIR = os.environ.get('OPENAPI_DIR') or '../openapi/'
