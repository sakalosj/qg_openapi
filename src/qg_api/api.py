import os

from connexion import NoContent
from connexion.decorators.security import validate_scope
from connexion.exceptions import OAuthProblem, OAuthScopeProblem

from qg_api.db import Vulner, Patch, Server, Scan, Report, session_scope, Base, engine


def admin_action(action: str):
    actions = {'create': create_all,
               'drop': drop_all,
               'test_action': lambda: 'test action called'
               }
    return actions[action]()


def create_all():
    print(os.getpid())
    print('trying to create')
    Base.metadata.create_all(engine)
    with session_scope() as session:
        Vulner.populate(session, 1000)
        Patch.populate(session, 50)
        Server.populate(session, 20)
    return 'CREATED!!!'


def drop_all():
    print(os.getpid())
    Base.metadata.drop_all(engine)
    return 'DROPED!!!'


def create_scan(body):
    with session_scope() as session:
        new_scan = Scan.from_dict(session, **body)
        session.add(new_scan)
        session.commit()
        new_scan.launch(session)
        new_scan.status = 'running'
        session.commit()
        return {'id': new_scan.id}


def get_scan(scan_id):
    with session_scope() as session:
        scan = session.query(Scan).get(scan_id)
        if scan:
            scan_dict = scan.to_dict()
            scan.status = 'finished'
            session.commit()
            return scan_dict
        else:
            return NoContent, 404


def create_report(body):
    with session_scope() as session:
        new_report = Report.from_dict(session, **body)
        session.add(new_report)
        session.commit()
        new_report.launch()
        session.commit()
        return {'id': new_report.id}


def get_report(report_id):
    with session_scope() as session:
        report = session.query(Report).get(report_id)
        if report:
            rep_dict = report.to_dict()
            report.status = 'finished'
            session.commit()
            return rep_dict
        else:
            return NoContent, 404


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
