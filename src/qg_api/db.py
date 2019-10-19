import random
from contextlib import contextmanager
from time import sleep

from sqlalchemy import func, inspect, create_engine, Column, String, Integer, ForeignKey, ForeignKeyConstraint, DateTime
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import scoped_session, sessionmaker, relationship, backref
from sqlalchemy.orm.collections import attribute_mapped_collection

from qg_api.cfg import QG_DB_URI

engine = create_engine(QG_DB_URI)
Base = declarative_base()
ScopedSession = scoped_session(sessionmaker(bind=engine))





@contextmanager
def session_scope():
    """Provide a transactional scope around a series of operations."""
    session = ScopedSession()
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()


class BaseMixin:
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    @classmethod
    def get_one_or_create(cls, session, **kwargs):
        instance = session.query(cls).filter_by(**kwargs).with_for_update().one_or_none()

        if not instance:
            pk = [key.name for key in inspect(cls).primary_key]
            q = session.query(cls).filter_by(**{key: value for key, value in kwargs.items() if key in pk})
            # check if kwargs contains pk and if pk is in db
            if set(pk).issubset(kwargs.keys()) and session.query(q.exists()).scalar():
                raise ValueError('attributes contain existing pk, but other values dont match db')
            instance = cls(**kwargs)
        return instance

    def __repr__(self):
        values = ', '.join("%s=%r" % (n, getattr(self, n)) for n in self.__table__.c.keys())
        return "%s(%s)" % (self.__class__.__name__, values)

class Server(BaseMixin, Base):
    """
    in prd application last_scan field should be changed to most recent existing scan if exist
    """

    ip = Column(String(30), primary_key=True, autoincrement=False)
    last_scan_fk = Column(Integer, ForeignKey('scan.id'))
    last_scan = relationship('Scan', backref=backref('_servers'))

    @classmethod
    def populate(cls, session, count):
        for ip in range(count):
            session.add(cls(ip=ip))
        session.commit()


class Scan(BaseMixin, Base):
    __tablename__ = 'scan'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(50))
    status = Column(String(15))
    launched = Column(DateTime(), server_default=func.now())

    servers = association_proxy('scan_servers', 'server', creator=lambda server: Scan2Server(server=server))
    servers_vulners = association_proxy('scan_servers_collection', 'vulners',
                                        creator=lambda ip, server: Scan2Server(server=server))
    servers_data = relationship('Scan2Server', collection_class=attribute_mapped_collection('server_ip_fk'),
                                cascade='all')

    @classmethod
    def populate(cls, session, count):
        for i in range(count):
            servers = Server.pick_random(random.randint(3, 10))
            new_scan = cls(title='rand scan {}'.format(i), status='new', servers=servers)
            new_scan.launch()
            session.add(new_scan)
        session.commit()


    @classmethod
    def from_dict(cls, session, servers=None, **kwargs):
        new_scan = cls(**kwargs)
        if not isinstance(servers, list) or servers == []:
            raise ValueError('No or incorrect servers')
        for server in servers:
            # srv = get_one_or_create(Server, **server)
            srv = Server.get_one_or_create(session, **server)
            new_scan.servers.append(srv)
        return new_scan

    def to_dict(self):
        scan_dict = {'id': self.id,
                     'title': self.title,
                     'status': self.status,
                     'launched': self.launched,
                     'servers': [{'ip': server.ip} for server in self.servers]}
        return scan_dict

    def launch(self, session):
        vulners = session.query(Vulner)
        session.query(Server).with_for_update().filter(Server.ip.in_([server.ip for server in self.servers])).all()
        # engine.execute('select * from server where  server.ip in ({}) for update '.format( ', '.join(['\'' + str(server.ip) + '\'' for server in self.servers])))
        for server in self.servers:
            server.last_scan = self
            for vulner in random.sample(vulners.all(), random.randint(1, 10)):
                self.servers_data[server.ip].vulners.append(vulner)
            session.commit()
        session.commit()


class Scan2Server(Base):
    __tablename__ = 'scan2server'

    scan_id_fk = Column(Integer, ForeignKey('scan.id'), primary_key=True)
    server_ip_fk = Column(String(30), ForeignKey('server.ip'), primary_key=True)
    status = Column(String(30))
    data = Column(String(30))
    error = Column(String(30))
    datetime = Column(DateTime)

    scan = relationship('Scan', backref=backref('scan_servers'))
    server = relationship('Server', backref=backref('server_scans'))

    scan_server_colletion = relationship('Scan', backref=backref('scan_servers_collection',
                                                                      collection_class=attribute_mapped_collection(
                                                                          'server_ip_fk')))

    vulners = association_proxy('scan_server2vulner', 'vulner', creator=lambda vulner: ScanServer2Vulner(vulner=vulner))


class ScanServer2Vulner(Base):
    __tablename__ = 'scan_server2vulner'

    scan2server_scan_id_fk = Column(Integer, primary_key=True)
    scan2server_server_ip_fk = Column(String(30), primary_key=True)
    vulner_qid_fk = Column(Integer, ForeignKey('vulner.qid'), primary_key=True)

    scan_servers = relationship('Scan2Server', backref=backref('scan_server2vulner', cascade='all'),
                                foreign_keys=[scan2server_scan_id_fk, scan2server_server_ip_fk])
    vulner = relationship('Vulner', backref=backref('scan_server2vulner'), foreign_keys=[vulner_qid_fk])

    __table_args__ = (ForeignKeyConstraint([scan2server_scan_id_fk, scan2server_server_ip_fk],
                                           [Scan2Server.scan_id_fk, Scan2Server.server_ip_fk]),
                      {})


class Report(BaseMixin, Base):
    id = Column(Integer, primary_key=True)
    title = Column(String(50))
    status = Column(String(30))
    launched = Column(DateTime, server_default=func.now())

    servers = association_proxy('report_servers', 'server', creator=lambda server: Report2Server(server=server))
    servers_data = relationship('Report2Server', collection_class=attribute_mapped_collection('server_ip_fk'),
                                cascade='all')

    @classmethod
    def from_dict(cls,session, servers=None, **kwargs):
        new_report = cls(**kwargs)
        if servers is None or servers == [] or not isinstance(servers, list):
            ValueError('No or incorrect servers')
        for ip in [server['ip'] for server in servers]:
            srv = Server.get_one_or_create(session, ip=ip)
            new_report.servers.append(srv)
        return new_report

    def to_dict(self):
        rep_dict = {'id': self.id,
                    'title': self.title,
                    'status': self.status,
                    'launched': self.launched,
                    'servers': {}}
        for ip, server_report in self.servers_data.items():
            rep_dict['servers'][ip] = {
                    'vulners': [vulner.to_dict() for vulner in server_report.vulners],
                    'patches': [patch.to_dict() for patch in server_report.patches]
                }

        return rep_dict

    def launch(self):
        patch_set = set()
        for server in self.servers:
            patch_set.clear()
            if not server.last_scan:
                continue  # dont query not scanned server
            # find latest scan and get all vulners
            vulners = server.last_scan.servers_data[server.ip].vulners
            for vulner in vulners:
                self.servers_data[server.ip].vulners.append(vulner)
                # self.servers_data[server.ip].patches.append(vulner.patch) # not efficient and sqlalchemy is not supporting ignore/update on duplicate id so it will fail in case of 2 vulners related to one patch
                patch_set.add(vulner.patch)
            for patch in patch_set:
                self.servers_data[server.ip].patches.append(patch)

    @classmethod
    def populate(cls, session, count):
        for i in range(count):
            servers = Server.pick_random(random.randint(3, 10))
            new_report = cls(title='rand report {}'.format(i), status='new', servers=servers)
            new_report.launch()
            session.add(new_report)
        session.commit()


class Report2Server(Base):
    __tablename__ = 'report2server'

    report_id_fk = Column(Integer, ForeignKey('report.id'), primary_key=True)
    server_ip_fk = Column(String(30), ForeignKey('server.ip'), primary_key=True)
    status = Column(String(30))
    data = Column(String(30))
    error = Column(String(30))
    datetime = Column(DateTime)

    report = relationship('Report', backref=backref('report_servers'))
    server = relationship('Server', backref=backref('server_reports'))

    patches = association_proxy('report_server2patch', 'patch', creator=lambda patch: ReportServer2Patch(patch=patch))
    vulners = association_proxy('report_server2vulner', 'vulner',
                                creator=lambda vulner: ReportServer2Vulner(vulner=vulner))


class Patch(Base):
    __tablename__ = 'patch'

    qid = Column(Integer, primary_key=True)
    severity = Column(Integer)
    title = Column(String(30))

    def to_dict(self):
        patch_dict = {'qid': self.qid,
                      'severity': self.severity,
                      'title': self.title}
        return patch_dict

    @staticmethod
    def populate(session, count):
        """

        :todo: add populating foreign keys of existing vulners
        """

        def split(a, n):
            k, m = divmod(len(a), n)
            return (a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

        vulners = session.query(Vulner).filter(Vulner.patch_qid == None).all()
        vulners_splited = split(vulners, count)
        for i in range(count):
            patch = (Patch(title='Patch {}'.format(i + 1), severity=random.randint(1, 5)))
            session.add(patch)
            for vulner in next(vulners_splited):
                patch.vulners.append(vulner)

        session.commit()


class ReportServer2Patch(Base):
    __tablename__ = 'report_server2patch'

    report2server_report_id_fk = Column(Integer, primary_key=True)
    report2server_server_ip_fk = Column(String(30), primary_key=True)
    patch_qid_fk = Column(Integer, ForeignKey('patch.qid'), primary_key=True)

    report_servers = relationship('Report2Server', backref=backref('report_server2patch', cascade='all'),
                                  foreign_keys=[report2server_report_id_fk, report2server_server_ip_fk])
    patch = relationship('Patch', backref=backref('report_servers2patch'), foreign_keys=[patch_qid_fk])

    __table_args__ = (ForeignKeyConstraint([report2server_report_id_fk, report2server_server_ip_fk],
                                           [Report2Server.report_id_fk, Report2Server.server_ip_fk]),
                      {})


class Vulner(Base):
    __tablename__ = 'vulner'

    qid = Column(Integer, primary_key=True)
    patch_qid = Column(Integer, ForeignKey('patch.qid'))
    severity = Column(Integer)
    title = Column(String(30))

    patch = relationship('Patch', backref='vulners')

    def to_dict(self):
        vuln_dict = {'qid': self.qid,
                     'patch_qid_fk': self.patch_qid,
                     'severity': self.severity,
                     'title': self.title,
                     }
        return vuln_dict

    @staticmethod
    def populate(session, count):
        for i in range(1, count + 1):
            session.add(Vulner(qid=i, title='Vulner {}'.format(i), severity=random.randint(1, 5)))
        session.commit()


class ReportServer2Vulner(Base):
    __tablename__ = 'report_server2vulner'

    report2server_report_id_fk = Column(Integer, primary_key=True)
    report2server_server_ip_fk = Column(String(30), primary_key=True)
    vulner_qid_fk = Column(Integer, ForeignKey('vulner.qid'), primary_key=True)

    report_servers = relationship('Report2Server', backref=backref('report_server2vulner', cascade='all'),
                                  foreign_keys=[report2server_report_id_fk, report2server_server_ip_fk])
    vulner = relationship('Vulner', backref=backref('report_server2vulner'), foreign_keys=[vulner_qid_fk])

    __table_args__ = (ForeignKeyConstraint([report2server_report_id_fk, report2server_server_ip_fk],
                                           [Report2Server.report_id_fk, Report2Server.server_ip_fk]),
                      {})



def create_all():
    with session_scope() as session:
        print('trying to create')
        Base.metadata.create_all(engine)
        Vulner.populate(1000)
        Patch.populate(50)
        Server.populate(20)


def drop_all():
    Base.metadata.drop_all()


Base.metadata.create_all(engine)
with session_scope() as session:
    if not session.query(Vulner).all():
        print('Table Vulner is empty, adding some data')
        Vulner.populate(session, 1000)

    if not session.query(Patch).all():
        print('Table Patch is empty, adding some data')
        Patch.populate(session, 50)
