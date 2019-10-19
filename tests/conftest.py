import connexion
import pytest

from app import SWG_DIR, QG_DB_URI
from qg_api.db import db


@pytest.fixture
def app():
    app = connexion.App(__name__, specification_dir=SWG_DIR)
    app.add_api('swagger.yaml', arguments={'title': 'qg_api'}, pythonic_params=True)
    app.app.config['SQLALCHEMY_DATABASE_URI'] = QG_DB_URI
    # db.init_app(app.app)
    return app.app
