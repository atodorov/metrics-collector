import json
import platform
import unittest

import agent

class BasicMetricsTestCase(unittest.TestCase):
    def test_basic_metrics_returns_dict(self):
        metrics = agent.basic_metrics()
        self.assertTrue(metrics['uptime'] > 0)
        self.assertTrue(metrics['cpu'] >= 0)
        self.assertTrue(metrics['memory'] > 0)
        self.assertEqual(platform.system(), metrics['system'])

class ParseEventXMLTestCase(unittest.TestCase):
    def test_parse_valid(self):
        xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
        <EventID>4672</EventID>
        <Version>0</Version>
        <Level>0</Level>
        <Task>12548</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8020000000000000</Keywords>
        <TimeCreated SystemTime='2017-07-01T14:26:05.774505000Z'/>
        <EventRecordID>47822</EventRecordID>
        <Correlation ActivityID='{9675755E-F26F-0000-8275-75966FF2D201}'/>
        <Execution ProcessID='708' ThreadID='748'/>
        <Channel>Security</Channel>
        <Computer>EC2AMAZ-BBN7IEM</Computer>
        <Security/>
    </System>
    <EventData>
        <Data Name='SubjectUserSid'>S-1-5-18</Data>
        <Data Name='SubjectUserName'>SYSTEM</Data>
        <Data Name='SubjectDomainName'>NT AUTHORITY</Data>
        <Data Name='SubjectLogonId'>0x3e7</Data>
        <Data Name='PrivilegeList'>SeAssignPrimaryTokenPrivilege
\r\n\t\t\tSeTcbPrivilege\r\n\t\t\tSeSecurityPrivilege\r\n\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r
\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeAuditPrivilege\r\n\t\t\tSeSys
temEnvironmentPrivilege\r\n\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege</Data>
    </EventData>
</Event>"""

        event = agent.parse_event_xml(xml)
        for key in ['EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords', 'TimeCreated',
                    'EventRecordID', 'Correlation', 'ProcessID', 'EventData']:
            self.assertIn(key, event)

        # EventData is a valid JSON string
        event_data = json.loads(event['EventData'])
        self.assertIsNot({}, event_data)


class WindowsEventLogsTestCase(unittest.TestCase):
    def test_returns_no_more_than_1000(self):
        if platform.system() != 'Windows':
            return

        events = agent.windows_event_logs(0, 1000)
        self.assertTrue(len(events) <= 1000)

        current_event_id = 0
        for evt in events:
            # the list is sorted
            self.assertTrue(evt['EventRecordID'] > current_event_id)
            current_event_id = evt['EventRecordID']

class MainTestCase(unittest.TestCase):
    def test_returns_valid_json(self):
        metrics = agent.main(['', 12345])

        # this is a valid JSON string
        metrics = json.loads(metrics)

        self.assertTrue(metrics['uptime'] > 0)
        self.assertTrue(metrics['cpu'] >= 0)
        self.assertTrue(metrics['memory'] > 0)
        self.assertEqual(platform.system(), metrics['system'])

        if platform.system() == 'Windows':
            self.assertTrue(len(metrics['security_event_logs']) <= 1000)
