import random

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, inspect
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.orm.collections import attribute_mapped_collection

db = SQLAlchemy()


# def get_or_create(model, **kwargs):
#     instance = query(model).filter_by(**kwargs).first()
#     if instance:
#         return instance
#     else:
#         instance = model(**kwargs)
#         session.add(instance)
#         session.commit()
#         return instance

def get_one_or_create(Model, **kwargs):
    instance = Model.query.filter_by(**kwargs).with_for_update().one_or_none()

    if not instance:
        # get primaty keys
        pk = [key.name for key in inspect(Model).primary_key]
        # query just using keys which are part of pk
        q = Model.query.filter_by(**{key: value for key, value in kwargs.items() if key in pk})
        # check if kwargs contains pk and if pk is in db
        if set(pk).issubset(kwargs.keys()) and q.all():  # Model.query(q.exists()).scalar():
            raise ValueError('attributes contain existing pk, but other values dont match db')
        instance = Model(**kwargs)
    return instance


class ModelMixin:
    @classmethod
    def get_one_or_create(cls, **kwargs):
        instance = cls.query.filter_by(**kwargs).with_for_update().one_or_none()

        if not instance:
            # get primaty keys
            pk = [key.name for key in inspect(cls).primary_key]
            # query just using keys which are part of pk
            q = cls.query.filter_by(**{key: value for key, value in kwargs.items() if key in pk})
            # check if kwargs contains pk and if pk is in db
            if set(pk).issubset(kwargs.keys()) and q.all():  # Model.query(q.exists()).scalar():
                raise ValueError('attributes contain existing pk, but other values dont match db')
            instance = cls(**kwargs)
        return instance

    def to_dict(self):
        raise NotImplementedError


class HelperMixin():
    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #
    #     if not issubclass(type(self), db.Model):
    #         raise Exception('Able to use only with sql alchemy model')
    #
    # @classmethod
    # def pick_random(cls, number):
    #     return cls.query.order_by(func.rand()).limit(number).all()
    pass


class ServerModel(ModelMixin, db.Model):
    """
    in prd application last_scan field should be changed to most recent existing scan if exist
    """
    __tablename__ = 'server'

    ip = db.Column(db.String(30), primary_key=True, autoincrement=False)
    last_scan_fk = db.Column(db.Integer, db.ForeignKey('scan.id'))
    last_scan = db.relationship('ScanModel', backref=db.backref('_servers'))

    @classmethod
    def populate(cls, count):
        for ip in range(count):
            db.session.add(cls(ip=ip))
        db.session.commit()


class ScanModel(ModelMixin, db.Model):
    __tablename__ = 'scan'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(50))
    status = db.Column(db.String(15))
    launched = db.Column(db.DateTime(), server_default=func.now())

    servers = association_proxy('scan_servers', 'server', creator=lambda server: Scan2Server(server=server))
    servers_vulners = association_proxy('scan_servers_collection', 'vulners',
                                        creator=lambda ip, server: Scan2Server(server=server))
    servers_data = db.relationship('Scan2Server', collection_class=attribute_mapped_collection('server_ip_fk'),
                                   cascade='all')

    @classmethod
    def populate(cls, count):
        for i in range(count):
            servers = ServerModel.pick_random(random.randint(3, 10))
            new_scan = cls(title='rand scan {}'.format(i), status='new', servers=servers)
            new_scan.launch()
            db.session.add(new_scan)
        # db.session.add(self)  # not necessary
        db.session.commit()

    @classmethod
    def scan_with_data(cls, servers, *args, **kwargs):
        new_scan = cls(*args, **kwargs)
        vulners = db.session.query(VulnerModel)
        for server in servers:
            new_scan.servers.append(server)
            db.session.commit()
            for vulner in random.sample(vulners.all(), 10):
                new_scan.servers_data[server.ip].vulners.append(vulner)
        db.session.add(new_scan)
        db.session.commit()
        return new_scan

    @classmethod
    def from_dict(cls, servers=None, **kwargs):
        new_scan = cls(**kwargs)
        if servers is None or servers == [] or not isinstance(servers, list):
            ValueError('No or incorrect servers')
        for server in servers:
            # srv = get_one_or_create(ServerModel, **server)
            srv = ServerModel.get_one_or_create(**server)
            new_scan.servers.append(srv)
        return new_scan

    def to_dict(self):
        scan_dict = {'id': self.id,
                     'title': self.title,
                     'status': self.status,
                     'launched': self.launched,
                     'servers': [{'ip': server.ip} for server in self.servers]}
        return scan_dict

    def launch(self):
        vulners = db.session.query(VulnerModel)
        ServerModel.query.with_for_update().filter(ServerModel.ip.in_([server.ip for server in self.servers])).all()
        # db.engine.execute('select * from server where  server.ip in ({}) for update '.format( ', '.join(['\'' + str(server.ip) + '\'' for server in self.servers])))
        for server in self.servers:
            server.last_scan = self
            for vulner in random.sample(vulners.all(), random.randint(1, 10)):
                self.servers_data[server.ip].vulners.append(vulner)
            db.session.commit()
        # db.session.add(self)  # not necessary
        db.session.commit()


class Scan2Server(db.Model):
    __tablename__ = 'scan2server'

    scan_id_fk = db.Column(db.Integer, db.ForeignKey('scan.id'), primary_key=True)
    server_ip_fk = db.Column(db.String(30), db.ForeignKey('server.ip'), primary_key=True)
    status = db.Column(db.String(30))
    data = db.Column(db.String(30))
    error = db.Column(db.String(30))
    datetime = db.Column(db.DateTime)

    scan = db.relationship('ScanModel', backref=db.backref('scan_servers'))
    server = db.relationship('ServerModel', backref=db.backref('server_scans'))

    scan_server_colletion = db.relationship('ScanModel', backref=db.backref('scan_servers_collection',
                                                                            collection_class=attribute_mapped_collection(
                                                                                'server_ip_fk')))

    vulners = association_proxy('scan_server2vulner', 'vulner', creator=lambda vulner: ScanServer2Vulner(vulner=vulner))


class ScanServer2Vulner(db.Model):
    __tablename__ = 'scan_server2vulner'

    scan2server_scan_id_fk = db.Column(db.Integer, primary_key=True)
    scan2server_server_ip_fk = db.Column(db.String(30), primary_key=True)
    vulner_qid_fk = db.Column(db.Integer, db.ForeignKey('vulner.qid'), primary_key=True)

    scan_servers = db.relationship('Scan2Server', backref=db.backref('scan_server2vulner', cascade='all'),
                                   foreign_keys=[scan2server_scan_id_fk, scan2server_server_ip_fk])
    vulner = db.relationship('VulnerModel', backref=db.backref('scan_server2vulner'), foreign_keys=[vulner_qid_fk])

    __table_args__ = (db.ForeignKeyConstraint([scan2server_scan_id_fk, scan2server_server_ip_fk],
                                              [Scan2Server.scan_id_fk, Scan2Server.server_ip_fk]),
                      {})


class ReportModel(ModelMixin, db.Model):
    __tablename__ = 'report'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    status = db.Column(db.String(30))
    launched = db.Column(db.DateTime, server_default=func.now())

    servers = association_proxy('report_servers', 'server', creator=lambda server: Report2Server(server=server))
    servers_data = db.relationship('Report2Server', collection_class=attribute_mapped_collection('server_ip_fk'),
                                   cascade='all')

    @classmethod
    def from_dict(cls, servers=None, **kwargs):
        new_report = cls(**kwargs)
        if servers is None or servers == [] or not isinstance(servers, list):
            ValueError('No or incorrect servers')
        for ip in [server['ip'] for server in servers]:
            # srv = get_one_or_create(ServerModel, **server)
            srv = ServerModel.get_one_or_create(ip=ip)
            new_report.servers.append(srv)
        return new_report

    def to_dict(self):
        rep_dict = {'id': self.id,
                    'title': self.title,
                    'status': self.status,
                    'launched': self.launched,
                    'servers': []}
        for ip, server_report in self.servers_data.items():
            rep_dict['servers'].append(
                {ip:{
                    'vulners':[vulner.to_dict() for vulner in server_report.vulners],
                    'patches': [patch.to_dict() for patch in server_report.patches]
                }}
            )
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
    def populate(cls, count):
        for i in range(count):
            servers = ServerModel.pick_random(random.randint(3, 10))
            new_report = cls(title='rand report {}'.format(i), status='new', servers=servers)
            new_report.launch()
            db.session.add(new_report)
        db.session.commit()


class Report2Server(db.Model):
    __tablename__ = 'report2server'

    report_id_fk = db.Column(db.Integer, db.ForeignKey('report.id'), primary_key=True)
    server_ip_fk = db.Column(db.String(30), db.ForeignKey('server.ip'), primary_key=True)
    status = db.Column(db.String(30))
    data = db.Column(db.String(30))
    error = db.Column(db.String(30))
    datetime = db.Column(db.DateTime)

    report = db.relationship('ReportModel', backref=db.backref('report_servers'))
    server = db.relationship('ServerModel', backref=db.backref('server_reports'))

    patches = association_proxy('report_server2patch', 'patch', creator=lambda patch: ReportServer2Patch(patch=patch))
    vulners = association_proxy('report_server2vulner', 'vulner',
                                creator=lambda vulner: ReportServer2Vulner(vulner=vulner))


class PatchModel(db.Model):
    __tablename__ = 'patch'

    qid = db.Column(db.Integer, primary_key=True)
    # vulners = db.relationship('VulnerModel', backref='patch')
    severity = db.Column(db.Integer)
    title = db.Column(db.String(30))

    # category = db.Column(db.String(30))
    # solution = db.Column(db.String(30))

    def to_dict(self):
        patch_dict = {'qid': self.qid,
                      'severity': self.severity,
                      'title': self.title}
        return patch_dict

    @staticmethod
    def populate(count):
        """

        :param count:
        :return:
        :todo: add populating foreign keys of existing vulners
        """

        def split(a, n):
            k, m = divmod(len(a), n)
            return (a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

        vulners = db.session.query(VulnerModel).filter(VulnerModel.patch_qid == None).all()
        vulners_splited = split(vulners, count)
        for i in range(count):
            patch = (PatchModel(title='Patch {}'.format(i + 1), severity=random.randint(1, 5)))
            db.session.add(patch)
            for vulner in next(vulners_splited):
                patch.vulners.append(vulner)

        db.session.commit()


class ReportServer2Patch(db.Model):
    __tablename__ = 'report_server2patch'

    report2server_report_id_fk = db.Column(db.Integer, primary_key=True)
    report2server_server_ip_fk = db.Column(db.String(30), primary_key=True)
    patch_qid_fk = db.Column(db.Integer, db.ForeignKey('patch.qid'), primary_key=True)

    report_servers = db.relationship('Report2Server', backref=db.backref('report_server2patch', cascade='all'),
                                     foreign_keys=[report2server_report_id_fk, report2server_server_ip_fk])
    patch = db.relationship('PatchModel', backref=db.backref('report_servers2patch'), foreign_keys=[patch_qid_fk])

    __table_args__ = (db.ForeignKeyConstraint([report2server_report_id_fk, report2server_server_ip_fk],
                                              [Report2Server.report_id_fk, Report2Server.server_ip_fk]),
                      {})


class VulnerModel(db.Model, HelperMixin):
    __tablename__ = 'vulner'

    qid = db.Column(db.Integer, primary_key=True)
    patch_qid = db.Column(db.Integer, db.ForeignKey('patch.qid'))
    severity = db.Column(db.Integer)
    cveid = db.Column(db.Integer)
    title = db.Column(db.String(30))
    category = db.Column(db.String(30))
    solution = db.Column(db.String(30))

    patch = db.relationship('PatchModel', backref='vulners')

    def to_dict(self):
        vuln_dict = {'qid': self.qid,
                     'patch_qid': self.patch_qid,
                     'severity': self.severity,
                     'cveid': self.cveid,
                     'title': self.title,
                     'category': self.category,
                     'solution': self.solution,
                     }
        return vuln_dict

    @staticmethod
    def populate(count):
        for i in range(1, count + 1):
            db.session.add(VulnerModel(qid=i, title='Vulner {}'.format(i), severity=random.randint(1, 5)))
        db.session.commit()


class ReportServer2Vulner(db.Model):
    __tablename__ = 'report_server2vulner'

    report2server_report_id_fk = db.Column(db.Integer, primary_key=True)
    report2server_server_ip_fk = db.Column(db.String(30), primary_key=True)
    vulner_qid_fk = db.Column(db.Integer, db.ForeignKey('vulner.qid'), primary_key=True)

    report_servers = db.relationship('Report2Server', backref=db.backref('report_server2vulner', cascade='all'),
                                     foreign_keys=[report2server_report_id_fk, report2server_server_ip_fk])
    vulner = db.relationship('VulnerModel', backref=db.backref('report_server2vulner'), foreign_keys=[vulner_qid_fk])

    __table_args__ = (db.ForeignKeyConstraint([report2server_report_id_fk, report2server_server_ip_fk],
                                              [Report2Server.report_id_fk, Report2Server.server_ip_fk]),
                      {})
