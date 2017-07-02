import unittest
import unittest.mock

import alerts

class AlertsTestCase(unittest.TestCase):

    @unittest.mock.patch('alerts._send_alert')
    def test_if_metric_over_limit_sends_alert(self, _send_alert): # pylint: disable=no-self-use
        metrics = {
            'cpu': 50,
            'memory': 75,
        }
        client = {
            'alerts': {
                'cpu': 30,
            }
        }

        alerts.check_for_alerts({}, client, metrics)
        _send_alert.assert_called_once_with({}, client, metrics, 'cpu')

    @unittest.mock.patch('alerts._send_alert')
    def test_if_metric_below_limit_doesnt_send_alert(self, _send_alert): # pylint: disable=no-self-use
        metrics = {
            'cpu': 30,
            'memory': 75,
        }
        client = {
            'alerts': {
                'cpu': 30,
            }
        }

        alerts.check_for_alerts({}, client, metrics)
        _send_alert.assert_not_called()

    @unittest.mock.patch('alerts._send_email')
    def test_if_metric_over_limit_sends_email(self, _send_email): # pylint: disable=no-self-use
        metrics = {
            'cpu': 50,
            'memory': 75,
        }
        client = {
            'ip': 'localhost',
            'mail': 'atodorov@example.com',
            'alerts': {
                'cpu': 30,
            }
        }

        alerts.check_for_alerts({}, client, metrics)
        _send_email.assert_called_once_with(
            {},
            'atodorov@example.com',
            'Monitoring warning for localhost: cpu too high',
            """cpu usage of 50 is greater than configured limit of 30!

Check-out what's going on with the system or increase the
limits!""")

    def test_invalid_smtp_fails(self): # pylint: disable=no-self-use
        metrics = {
            'cpu': 50,
            'memory': 75,
        }
        client = {
            'ip': 'localhost',
            'mail': 'atodorov@example.com',
            'alerts': {
                'cpu': 30,
            }
        }
        smtp = {
            'from': 'testing@example.com',
            'host': 'localhost',
            'port': 252525,
            'username': 'tester',
            'password': 'invalid-password',
            'starttls': False,
        }

        with self.assertRaises(ConnectionRefusedError):
            alerts.check_for_alerts(smtp, client, metrics)
