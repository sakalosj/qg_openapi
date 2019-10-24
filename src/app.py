#!../venv/bin/python
import os

import connexion

from qg_api.cfg import SWG_DIR
from qg_api.db import ScopedSession

app = connexion.App(__name__, specification_dir=SWG_DIR)
app.add_api('openapi.yaml', arguments={'title': 'qg_api'}, pythonic_params=True)
application = app.app

@app.app.teardown_appcontext
def cleanup(resp_or_exc):
    ScopedSession.remove()

@app.app.before_request
def br():
    print('!!!!!!!!!!!!!!!!!!!!!!!   ' + str(os.getpid()) + '   !!!!!!!!!!!!!!!!!!!!')

if __name__ == '__main__':
    app.run(port=2010)
