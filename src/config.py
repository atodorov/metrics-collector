import os
import xml.etree.ElementTree as ET


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
            try:
                if not client_config.attrib[key]:
                    raise RuntimeError('Empty attribute %s for %s' % (
                        key, ET.tostring(client_config)))

                client[key] = client_config.attrib[key]
            except KeyError:
                raise RuntimeError('Missing attribute %s for %s' % (
                    key, ET.tostring(client_config)))

        client['alerts'] = {}
        for alert in client_config.findall('alert'):
            try:
                _type = alert.attrib['type']
                _limit = float(alert.attrib['limit'].replace('%', ''))
            except KeyError:
                raise RuntimeError('Invalid type or limit attributes for %s' % ET.tostring(alert))

            client['alerts'][_type] = _limit

        clients.append(client)

    return clients


def parse_db(config):
    """
        Returns the DB connection string from the XML configuration!
    """
    database = config.find('database')

    if database is None:
        raise RuntimeError('Missing database XML tag')

    if 'connection' not in database.attrib:
        raise RuntimeError('Missing <database> connection attribute')

    if not database.attrib['connection']:
        raise RuntimeError('<database> connection is empty')

    return database.attrib['connection']



def parse_smtp(config):
    """
        Returns outgoing SMTP configuration dict from the XML configuration!
    """
    _smtp = config.find('smtp')

    if _smtp is None:
        raise RuntimeError('Missing smtp XML tag')

    smtp_cfg = {}
    try:
        for attrib in ['host', 'username', 'password']:
            if not _smtp.attrib[attrib]:
                raise RuntimeError('Empty <smtp> attribute %s' % attrib)

            smtp_cfg[attrib] = _smtp.attrib[attrib]
    except KeyError:
        raise RuntimeError('Missing <smtp> attribute %s' % attrib)

    smtp_cfg['port'] = int(_smtp.attrib.get('port', 25))
    smtp_cfg['from'] = _smtp.attrib.get('from', smtp_cfg['username'])
    if smtp_cfg['from'].find('@') == -1:
        raise RuntimeError('Invalid from address or username - missing @')

    smtp_cfg['starttls'] = _smtp.attrib.get('starttls', 'no') == 'yes'

    return smtp_cfg
