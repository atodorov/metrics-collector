import tempfile
import unittest
import xml.etree.ElementTree as ET

import config

def _create_xml(xml):
    _, _filename = tempfile.mkstemp(prefix='config.xml-')
    f = open(_filename, 'w')
    f.write(xml.strip())
    f.close()
    return _filename


class ConfigTestCase(unittest.TestCase):
    def test_parse_config_non_existing_path(self):
        with self.assertRaisesRegex(RuntimeError, "File .* not found!"):
            config.parse_config('/tmp/non-existing.xml')

    def test_parse_config_invalid_xml(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config> </conf>
"""
        filename = _create_xml(xml)
        with self.assertRaisesRegex(RuntimeError, "Invalid XML for .*"):
            config.parse_config(filename)

    def test_parse_config_valid_xml(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config></config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        self.assertIsInstance(xml_root, ET.Element)

class ParseDBTestCase(unittest.TestCase):
    def test_missing_database_tag(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config></config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Missing database XML tag'):
            config.parse_db(xml_root)

    def test_missing_connection_attribute(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <database />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Missing <database> connection attribute'):
            config.parse_db(xml_root)

    def test_empty_connection_string(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <database connection="" />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, '<database> connection is empty'):
            config.parse_db(xml_root)

    def test_valid(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <database connection="sqlite:////tmp/example.db" />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        connection = config.parse_db(xml_root)
        self.assertEqual('sqlite:////tmp/example.db', connection)


class ParseSMTPTestCase(unittest.TestCase):
    def test_missing_smtp_tag(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config></config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Missing smtp XML tag'):
            config.parse_smtp(xml_root)

    def test_empty_smtp_tag(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <smtp />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Missing <smtp> attribute .*'):
            config.parse_smtp(xml_root)

    def test_empty_smtp_attribute(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <smtp host='smtp.gmail.com' username='atodorov' password='' />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Empty <smtp> attribute password'):
            config.parse_smtp(xml_root)

    def test_invalid_from_attribute_via_username(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <smtp host='smtp.gmail.com' username='atodorov' password='example' />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Invalid from address .*'):
            config.parse_smtp(xml_root)

    def test_invalid_from_attribute_via_from(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <smtp host='smtp.gmail.com' username='atodorov@example.com' password='example' from='invalid' />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Invalid from address .*'):
            config.parse_smtp(xml_root)


    def test_valid_smtp(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <smtp host='smtp.gmail.com' username='atodorov@example.com' password='example'/>
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        smtp = config.parse_smtp(xml_root)
        self.assertEqual('smtp.gmail.com', smtp['host'])
        self.assertEqual('atodorov@example.com', smtp['username'])
        # by default from address comes from username
        self.assertEqual('atodorov@example.com', smtp['from'])
        self.assertEqual('example', smtp['password'])
        # port 25 is the default
        self.assertEqual(25, smtp['port'])

        # STARTTLS defaults to False if not specified
        self.assertFalse(smtp['starttls'])


class ParseClientsTestCase(unittest.TestCase):
    def test_no_clients_returns_empty_list(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config> </config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        clients = config.parse_clients(xml_root)
        self.assertEqual([], clients)

    def test_client_is_missing_attributes(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <client ip='locahost' />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Missing attribute .* for .*<client.*'):
            config.parse_clients(xml_root)

    def test_client_has_empty_attributes(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <client ip='' />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(RuntimeError, 'Empty attribute .* for .*<client.*'):
            config.parse_clients(xml_root)

    def test_valid_without_alerts(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <client
        ip='localhost'
        username='atodorov'
        password='example'
        mail='atodorov@example.com'
        platform='Linux' />
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        clients = config.parse_clients(xml_root)
        self.assertEqual(1, len(clients))
        self.assertEqual('localhost', clients[0]['ip'])
        # port defaults to 22
        self.assertEqual(22, clients[0]['port'])
        self.assertEqual('atodorov', clients[0]['username'])
        self.assertEqual('example', clients[0]['password'])
        self.assertEqual('atodorov@example.com', clients[0]['mail'])
        self.assertEqual({}, clients[0]['alerts'])

    def test_valid_with_alerts(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <client
        ip='localhost'
        username='atodorov'
        password='example'
        mail='atodorov@example.com'
        platform='Linux'>
            <alert type="memory" limit="80%" />
            <alert type="cpu" limit="50%" />
    </client>

    <client
        ip='localhost'
        username='atodorov'
        password='example'
        mail='atodorov@example.com'
        platform='Windows'>
            <alert type="memory" limit="80%" />
            <alert type="cpu" limit="50%" />
    </client>
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        clients = config.parse_clients(xml_root)
        self.assertEqual(2, len(clients))
        self.assertEqual('Linux', clients[0]['platform'])
        self.assertEqual('Windows', clients[1]['platform'])
        self.assertEqual({'memory': 80, 'cpu': 50}, clients[0]['alerts'])

    def test_invalid_alert_attributes(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <client
        ip='localhost'
        username='atodorov'
        password='example'
        mail='atodorov@example.com'
        platform='Linux'>
            <alert t="memory" limit="80%" />
    </client>
</config>
"""
        filename = _create_xml(xml)
        xml_root = config.parse_config(filename)
        with self.assertRaisesRegex(
            RuntimeError,
            'Invalid type or limit attributes for .*<alert.*'):
            config.parse_clients(xml_root)
