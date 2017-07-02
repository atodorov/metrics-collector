#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import paramiko
from datetime import datetime

import orm
import alerts
import config



def agent_scp(ssh, client, destination):
    """
        Secure copy the agent.py script to the client.

        @ssh - paramiko.SSHClient object
        @client - dict - configuration of client
        @destination - string - destination file name
        @return - None
    """
    sftp = ssh.open_sftp()
    sftp.put('agent.py', destination)
    sftp.close()


def collect_metrics(ssh, client, last_event_record_id):
    """
        SSH to the client and collect the metrics.

        @ssh - paramiko.SSHClient object
        @client - dict - configuration of client
        @last_event_record_id - int - EventRecordID for filtering
        @return - dict - metrics and windows security event log
    """

    ssh.connect(client['ip'], port=client['port'],
                username=client['username'], password=client['password'])

    print('***** DEBUG after connect')

    if client['platform'] == 'Linux':
        destination = '/tmp/agent.py'
    elif client['platform'] == 'Windows':
        destination = 'C:\\agent.py'
    else:
        raise RuntimeError('Unknown platform "%s" for %s' % (client['platform'], client['ip']))


    # copy the agent script to the client system
    agent_scp(ssh, client, destination)

    print('***** DEBUG after copy')

    # don't encrypt on the client b/c we're running through ssh
    # which is already encryted. The requirement says the client should
    # encrypt the response but that is not necessary! See the design doc.
    _in, _out, _err = ssh.exec_command("python %s %d" % (destination, last_event_record_id))

    # check for errors on the client
    errors = _err.read().strip().decode('utf8')
    if errors:
        raise RuntimeError('Execution on %s failed with:\n%s' % (client['ip'], errors))

    response = _out.read().strip().decode('utf8')

    ssh.close()

    print('***** DEBUG before return')

    return json.loads(response)




if __name__ == "__main__":
    # parse the XML configuration
    config_xml = config.parse_config('../config.xml')
    clients = config.parse_clients(config_xml)
    smtp_cfg = config.parse_smtp(config_xml)

    # connect to the DB
    db = orm.connect(config.parse_db(config_xml))


    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for client in clients:
        system = db.query(orm.System).filter_by(name=client['ip']).first()
        if not system:
            system = orm.System(name=client['ip'])
            db.add(system)
            db.commit()

        last_event_record_id = 0
        if client['platform'] == 'Windows':
            last_event = db.query(orm.WinEventLog).filter_by(
                system_id=system.id
            ).order_by(
                orm.WinEventLog.EventRecordID.desc()
            ).first()

            if last_event:
                last_event_record_id = last_event.EventRecordID


        metrics = collect_metrics(ssh, client, last_event_record_id)
        now = datetime.now()

        # save metrics to DB
        db.add(orm.CpuUsage(system_id=system.id, usage=metrics['cpu'], collected_at=now))
        db.add(orm.MemUsage(system_id=system.id, usage=metrics['memory'], collected_at=now))
        db.add(orm.Uptime(system_id=system.id, uptime=metrics['uptime'], collected_at=now))
        db.commit()

        # check for alerts
        alerts.check_for_alerts(smtp_cfg, client, metrics)

        # chech for event logs
        if 'security_event_logs' in metrics:
            for event_log in metrics['security_event_logs']:
                event_log['TimeCreated'] = datetime.strptime(event_log['TimeCreated'], '%Y-%m-%dT%H:%M:%S.%f')

                event = db.query(orm.WinEventLog).filter_by(
                    system_id=system.id,
                    EventRecordID=event_log['EventRecordID'],
                    TimeCreated=event_log['TimeCreated']
                ).first()

                if not event:
                    event = orm.WinEventLog(**event_log)
                    event.system_id = system.id
                    event.collected_at = now
                    db.add(event)
            db.commit()
