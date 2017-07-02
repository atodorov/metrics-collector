#!/usr/bin/env python

from __future__ import print_function

import json
import psutil
import platform
from datetime import datetime
import xml.etree.ElementTree as ET


# this is a timedelta object
uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())

metrics = {
    'system': platform.system(),
    'cpu': psutil.cpu_percent(interval=0.5),
    'memory': psutil.virtual_memory().percent,
    'uptime': uptime.days*24*3600 + uptime.seconds,
}


# collect Windows Security Event logs
if platform.system() == 'Windows':
    import sys
    from winevt import EventLog

    xmlns = {'_': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    batch_size = 1000
    last_event_record_id = 0
    if len(sys.argv) == 2:
        last_event_record_id = int(sys.argv[1])

    metrics['security_event_logs'] = []

    event_cnt = 0
    events = {}
    for event in EventLog.Query('Security', "Event/System[EventRecordID>%d]" % last_event_record_id):
        event_xml = ET.fromstring(event.xml)

        event_log = {}

        # integer properties
        for tag in ['EventID', 'Version', 'Level', 'Task', 'Opcode', 'EventRecordID']:
            event_log[tag] = int(event_xml.find('_:System/_:%s' % tag, xmlns).text)

        # string properties
        for tag in ['Keywords', 'Computer', 'Security']:
            event_log[tag] = event_xml.find('_:System/_:%s' % tag, xmlns).text

        # other properties
        event_log['TimeCreated'] = event_xml.find('_:System/_:TimeCreated', xmlns).attrib['SystemTime'][:-4]

        try:
            event_log['Correlation'] = event_xml.find('_:System/_:Correlation', xmlns).attrib['ActivityID']
        except KeyError:
            event_log['Correlation'] = None

        event_log['ProcessID'] = int(event_xml.find('_:System/_:Execution', xmlns).attrib['ProcessID'])

        #event log data in JSON format
        event_data = {}
        for data in event_xml.findall('_:EventData/_:Data', xmlns):
            event_data[data.attrib['Name']] = data.text
        if 'PrivilegeList' in event_data:
            event_data['PrivilegeList'] = event_data['PrivilegeList'].replace('\t', '').replace('\r', '').split('\n')
        event_log['EventData'] = json.dumps(event_data)

        events[event_log['EventRecordID']] = event_log

    # now sort all events
    event_record_ids = list(events.keys())
    event_record_ids.sort()

    # take only @batch number of events and append them to the metrics
    for id in event_record_ids[:batch_size]:
        metrics['security_event_logs'].append(events[id])


print(json.dumps(metrics))
