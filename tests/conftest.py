import connexion
import pytest

from qg_api.cfg import SWG_DIR, QG_DB_URI


@pytest.fixture
def app():
    app = connexion.App(__name__, specification_dir=SWG_DIR)
    app.add_api('openapi.yaml', arguments={'title': 'qg_api'}, pythonic_params=True)
    app.app.config['SQLALCHEMY_DATABASE_URI'] = QG_DB_URI
    # db.init_app(app.app)
    return app.app
