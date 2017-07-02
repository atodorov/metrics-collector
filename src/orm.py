import sqlalchemy as sql
from sqlalchemy.ext.declarative import declarative_base

_Base = declarative_base()


class System(_Base):
    __tablename__ = 'system'

    id = sql.Column(sql.Integer, primary_key=True)
    name = sql.Column(sql.String, unique=True)


class CpuUsage(_Base):
    __tablename__ = 'cpu_usage'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)
    usage = sql.Column(sql.Float, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)


class MemUsage(_Base):
    __tablename__ = 'mem_usage'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)
    usage = sql.Column(sql.Float, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)

class Uptime(_Base):
    __tablename__ = 'uptime'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)
    uptime = sql.Column(sql.Integer, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)


class WinEventLog(_Base):
    __tablename__ = 'win_event_log'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)

    # integer properties
    EventID = sql.Column(sql.Integer, index=True)
    Version = sql.Column(sql.Integer)
    Level = sql.Column(sql.Integer, index=True)
    Task = sql.Column(sql.Integer, index=True)
    Opcode = sql.Column(sql.Integer, index=True)
    EventRecordID = sql.Column(sql.Integer, index=True)
    ProcessID = sql.Column(sql.Integer)

    # string properties
    Keywords = sql.Column(sql.Text)
    Computer = sql.Column(sql.Text)
    Security = sql.Column(sql.Text)
    Correlation = sql.Column(sql.Text)

    # this holds JSON values
    # For PostgreSQL and some versions of MySQL there is
    # a generic JSON column type
    EventData = sql.Column(sql.Text)

    # datetime properties
    TimeCreated = sql.Column(sql.DateTime, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)


def connect(db_connection):
    """
        Connects to the database, creating the schema if it
        doesn't exist and returns a session object!

        A session object can be used to query, insert and delete
        records from the database!
    """
    db_engine = sql.create_engine(db_connection)
    _Base.metadata.create_all(db_engine)
    return sql.orm.sessionmaker(bind=db_engine)()
