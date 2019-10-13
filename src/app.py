#!../venv/bin/python
import os

import connexion

from qg_api.db import db

QG_DB_URI = os.environ.get('QG_DB_URI') or 'mysql+pymysql://root:123456@localhost:3309/qualys_guard'
print('db uri dir ', QG_DB_URI)
SWG_DIR = os.environ.get('SWG_DIR') or '../swagger/'
print('swg dir ', SWG_DIR)

app = connexion.App(__name__, specification_dir=SWG_DIR)
# app.app.json_encoder = encoder.JSONEncoder
app.add_api('swagger.yaml', arguments={'title': 'qg_api'}, pythonic_params=True)
app.app.config['SQLALCHEMY_DATABASE_URI'] = QG_DB_URI
db.init_app(app.app)
application = app.app

if __name__ == '__main__':
    app.run(port=8080)
