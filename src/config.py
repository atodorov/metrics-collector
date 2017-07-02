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
