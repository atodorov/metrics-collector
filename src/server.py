#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import smtplib
import paramiko
import sqlalchemy as sql
from datetime import datetime
import xml.etree.ElementTree as ET
from email.message import EmailMessage
from sqlalchemy.ext.declarative import declarative_base


def parse_config(config_path):
    """
        Parse a XML config file

        @config_path - string - the configuration filename
        @return - Element - the XML config root node!
    """

    if not os.path.exists(config_path):
        raise RuntimeError('File "%s" not found!' % config_path)

    try:
        return ET.parse(config_path).getroot()
    except:
        raise RuntimeError('Invalid XML for "%s"' % config_path)

def parse_clients(config):
    """
        Return clients configuration dict

        @config - Element - the <config> element from the XML
        @return - list - list of dicts describing each client
    """
    clients = []
    for client_config in config.findall('client'):
        client = {'port': int(client_config.attrib.get('port', 22))}

        for key in ['ip', 'username', 'password', 'mail', 'platform']:
            client[key] = client_config.attrib[key]

        client['alerts'] = {}
        for alert in client_config.findall('alert'):
            _type = alert.attrib['type']
            _limit = float(alert.attrib['limit'].replace('%', ''))
            client['alerts'][_type] = _limit

        clients.append(client)

    return clients


def parse_db(config):
    """
        Returns the DB connection string from the XML configuration!
    """
    return config.find('database').attrib['connection']


def parse_smtp(config):
    """
        Returns outgoing SMTP configuration dict from the XML configuration!
    """
    _smtp = config.find('smtp')

    smtp_cfg = {}
    for attrib in ['host', 'username', 'password']:
        smtp_cfg[attrib] = _smtp.attrib[attrib]
    smtp_cfg['port'] = int(_smtp.attrib.get('port', 25))
    smtp_cfg['from'] = _smtp.attrib.get('from', smtp_cfg['username'])
    smtp_cfg['starttls'] = _smtp.attrib.get('starttls', 'no') == 'yes'

    return smtp_cfg


def agent_scp(ssh, client):
    """
        Secure copy the agent.py script to the client.

        @ssh - paramiko.SSHClient object
        @client - dict - configuration of client
        @return - None
    """
    sftp = ssh.open_sftp()

    if client['platform'] == 'Linux':
        sftp.put('agent.py', '/tmp/agent.py')
    elif client['platform'] == 'Windows':
        sftp.put('agent.py', 'C:\\agent.py')
    else:
        raise RuntimeError('Unknown platform "%s" for %s' % (client['platform'], client['ip']))

    sftp.close()


def collect_metrics(ssh, client, system_id):
    """
        SSH to the client and collect the metrics.

        @ssh - paramiko.SSHClient object
        @client - dict - configuration of client
        @system_id - int - PK of system in DB
        @return - dict - metrics and windows security event log
    """

    ssh.connect(client['ip'], port=client['port'],
                username=client['username'], password=client['password'])

    print('***** DEBUG after connect')

    # copy the agent script to the client system
    agent_scp(ssh, client)

    print('***** DEBUG after copy')

    # don't encrypt on the client b/c we're running through ssh
    # which is already encryted. The requirement says the client should
    # encrypt the response but that is not necessary! See the design doc.

    if client['platform'] == 'Linux':
        _in, _out, _err = ssh.exec_command("python /tmp/agent.py")
    elif client['platform'] == 'Windows':
        last_event = db.query(WinEventLog).filter_by(
            system_id=system_id
        ).order_by(
            WinEventLog.EventRecordID.desc()
        ).first()

        if last_event:
            last_event_record_id = last_event.EventRecordID
        else:
            last_event_record_id = 0

        _in, _out, _err = ssh.exec_command("python C:\\agent.py %d" % last_event_record_id)
    else:
        raise RuntimeError('Unknown platform "%s" for %s' % (client['platform'], client['ip']))

    # check for errors on the client
    errors = _err.read().strip().decode('utf8')
    if errors:
        raise RuntimeError('Execution on %s failed with:\n%s' % (client['ip'], errors))

    response = _out.read().strip().decode('utf8')

    ssh.close()

    print('***** DEBUG before return')

    return json.loads(response)


SQLBase = declarative_base()


class System(SQLBase):
    __tablename__ = 'system'

    id = sql.Column(sql.Integer, primary_key=True)
    name = sql.Column(sql.String, unique=True)


class CpuUsage(SQLBase):
    __tablename__ = 'cpu_usage'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)
    usage = sql.Column(sql.Float, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)


class MemUsage(SQLBase):
    __tablename__ = 'mem_usage'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)
    usage = sql.Column(sql.Float, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)

class Uptime(SQLBase):
    __tablename__ = 'uptime'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)
    uptime = sql.Column(sql.Integer, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)


class WinEventLog(SQLBase):
    __tablename__ = 'win_event_log'

    id = sql.Column(sql.Integer, primary_key=True)
    system_id = sql.Column(sql.Integer, sql.ForeignKey('system.id'), nullable=False)


    EventID = sql.Column(sql.Integer, index=True)
    Version = sql.Column(sql.Integer)
    Level = sql.Column(sql.Integer, index=True)
    Task = sql.Column(sql.Integer, index=True)
    Opcode = sql.Column(sql.Integer, index=True)
    EventRecordID = sql.Column(sql.Integer, index=True)
    ProcessID = sql.Column(sql.Integer)


    # todo: string props, how long ???
    Keywords = sql.Column(sql.Text)
    Computer = sql.Column(sql.Text)
    Security = sql.Column(sql.Text)
    Correlation = sql.Column(sql.Text)
    # this holds JSON values.
    # For PostgreSQL and some versions of MySQL there is
    # a generic JSON column type
    EventData = sql.Column(sql.Text)

    # datetime properties.
    TimeCreated = sql.Column(sql.DateTime, index=True)
    collected_at = sql.Column(sql.DateTime, index=True, nullable=False)



def send_alert(smtp_cfg, client, metrics, _type):
    """
        Send email to the client when the metric of type
        @_type is greater than the configured limit!

        @smtp_cfg - dict - configuration of outgoing smtp
        @client - dict - client configuration
        @metrics - dict - all client metrics
        @_type - string - the metric type which triggered the alert
    """
    to = client['mail']
    subject = 'Monitoring warning for %s: %s too high' % (client['ip'], _type)
    body = """%s usage of %s is greater than configured limit of %s!

Check-out what's going on with the system or increase the
limits!""" % (_type, metrics[_type], client['alerts'][_type])

    send_email(smtp_cfg, to, subject.strip(), body)



def send_email(cfg, to, subject, body):
    msg = EmailMessage()
    msg['From'] = cfg['from']
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)

#TODO: smtp can raise here
    with smtplib.SMTP(cfg['host'], cfg['port']) as smtp:
        if cfg['starttls']:
            smtp.starttls()

        smtp.login(cfg['username'], cfg['password'])
        smtp.send_message(msg)


if __name__ == "__main__":
    config_xml = parse_config('config.xml')
    clients = parse_clients(config_xml)
    db_connection = parse_db(config_xml)
    smtp_cfg = parse_smtp(config_xml)

    db_engine = sql.create_engine(db_connection, echo=True)
    SQLBase.metadata.create_all(db_engine)
    db = sql.orm.sessionmaker(bind=db_engine)()


    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for client in clients:
        system = db.query(System).filter_by(name=client['ip']).first()
        if not system:
            system = System(name=client['ip'])
            db.add(system)
            db.commit()

        metrics = collect_metrics(ssh, client, system.id)
        now = datetime.now()


        cpu = CpuUsage(system_id=system.id, usage=metrics['cpu'], collected_at=now)
        db.add(cpu)

        memory = MemUsage(system_id=system.id, usage=metrics['memory'], collected_at=now)
        db.add(memory)

        uptime = Uptime(system_id=system.id, uptime=metrics['uptime'], collected_at=now)
        db.add(uptime)
        db.commit()

        for _type, _limit in client['alerts'].items():
            if metrics[_type] > _limit:
                send_alert(smtp_cfg, client, metrics, _type)

        if 'security_event_logs' in metrics:
            for event_log in metrics['security_event_logs']:
                event_log['TimeCreated'] = datetime.strptime(event_log['TimeCreated'], '%Y-%m-%dT%H:%M:%S.%f')

                event = db.query(WinEventLog).filter_by(
                    system_id=system.id,
                    EventRecordID=event_log['EventRecordID'],
                    TimeCreated=event_log['TimeCreated']
                ).first()

                if not event:
                    event = WinEventLog(**event_log)
                    event.system_id = system.id
                    event.collected_at = now
                    db.add(event)
            db.commit()
