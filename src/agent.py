#!/usr/bin/env python

from __future__ import print_function

import sys
import json
import psutil
import platform
from datetime import datetime
import xml.etree.ElementTree as ET

def basic_metrics():
    """
        Retuns a dict with basic metrics like
        CPU and memory usage!
    """
    # this is a timedelta object
    uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())

    return {
        'system': platform.system(),                    # Windows, Linux, etc
        'cpu': psutil.cpu_percent(interval=0.5),        # a percent
        'memory': psutil.virtual_memory().percent,      # a percent
        'uptime': uptime.days*24*3600 + uptime.seconds, # in seconds
    }


def parse_event_xml(xml):
    """
        Parse the event XML and return it as dict!

        @xml - string
        @return - dict
    """
    xmlns = {'_': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    event_log = {}
    event_xml = ET.fromstring(xml)

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

    # event log data in JSON format
    event_data = {}
    for data in event_xml.findall('_:EventData/_:Data', xmlns):
        event_data[data.attrib['Name']] = data.text
    if 'PrivilegeList' in event_data:
        event_data['PrivilegeList'] = event_data['PrivilegeList'].replace('\t', '').replace('\r', '').split('\n')
    event_log['EventData'] = json.dumps(event_data)

    return event_log


def trim_down_events(events, batch_size):
    """
        Trim down the events dictionary to the specified
        batch size starting from the lowest EventRecordID!

        @events - dict - key is the EventRecordID, value is the event dict
        @batch_size - int - how many events to return
    """
    # sort all EventRecordIDs
    event_record_ids = list(events.keys())
    event_record_ids.sort()

    # take only @batch_size number of events and append them to the metrics
    results = []
    for id in event_record_ids[:batch_size]:
        results.append(events[id])

    return results


def windows_event_logs(last_event_record_id, batch_size=1000):
    """
        Queries Windows Security Event logs and
        returns a list of events represented as
        dictionaries!
    """
    from winevt import EventLog

    events = {}
    for event in EventLog.Query('Security', "Event/System[EventRecordID>%d]" % last_event_record_id):
        event_log = parse_event_xml(event.xml)
        events[event_log['EventRecordID']] = event_log
        # NOTE: I don't know if Windows will return the events in a sorted order
        # or not, that's why I've implemented my own sort & trim function!
        # If it turns out Windows always guarantees the order we can use
        # a simple counter and break out of the loop once we reach the treshold!

    return trim_down_events(events, batch_size)



def main(argv=sys.argv):
    """
        Collect all metrics and return them as
        a JSON dump.
    """
    metrics = basic_metrics()

    # collect Windows Security Event logs
    if metrics['system'] == 'Windows':
        last_event_record_id = 0
        if len(argv) == 2:
            last_event_record_id = int(argv[1])

        metrics['security_event_logs'] = windows_event_logs(last_event_record_id)

    return json.dumps(metrics)


if __name__ == '__main__':
    print(main())
