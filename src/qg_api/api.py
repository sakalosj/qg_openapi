import pprint

from connexion.decorators.security import validate_scope
from connexion.exceptions import OAuthProblem, OAuthScopeProblem

from qg_api.db import ScanModel, get_one_or_create, db, ReportModel
from qg_api.db import db, VulnerModel, PatchModel, ServerModel


def admin_action(action: str) -> None:
    actions = {'create': create_all,
               'drop':drop_all}
    actions[action]()


def create_all():
    print('tring to create')
    db.create_all()
    VulnerModel.populate(1000)
    PatchModel.populate(50)
    ServerModel.populate(20)


def drop_all():
    db.drop_all()


def create_scan(body):
    new_scan = ScanModel.from_dict(**body.to_dict())
    db.session.add(new_scan)
    db.session.commit()
    new_scan.launch()
    new_scan.status = 'running'
    db.session.commit()
    return {'id': new_scan.id}


def get_scan(scan_id):
    scan = ScanModel.query.get(scan_id)
    if scan:
        scan_dict = scan.to_dict()
        scan.status = 'finished'
        db.session.commit()
        return scan_dict


def create_report(body):
    new_report = ReportModel.from_dict(**body.to_dict())
    db.session.add(new_report)
    db.session.commit()
    new_report.launch()
    db.session.commit()
    return {'id': new_report.id}

def get_report(report_id):
    report = ReportModel.query.get(report_id)
    if report:
        rep_dict = report.to_dict()
        report.status = 'finished'
        db.session.commit()
        return rep_dict


TOKEN_DB = {
    'asdf1234567890': {
        'uid': 100
    }
}


def apikey_auth(token, required_scopes):
    info = TOKEN_DB.get(token, None)

    if not info:
        raise OAuthProblem('Invalid token')

    return info


def basic_auth(username, password, required_scopes=None):
    if username == 'admin' and password == 'secret':
        info = {'sub': 'admin', 'scope': 'secret'}
    elif username == 'foo' and password == 'bar':
        info = {'sub': 'user1', 'scope': ''}
    else:
        # optional: raise exception for custom error response
        return None

    # optional
    if required_scopes is not None and not validate_scope(required_scopes, info['scope']):
        raise OAuthScopeProblem(
                description='Provided user doesn\'t have the required access rights',
                required_scopes=required_scopes,
                token_scopes=info['scope']
            )

    return info