import smtplib
from email.message import EmailMessage

def _send_email(cfg, to, subject, body):
    """
        Sends an email using specified SMTP configuration
    """
    msg = EmailMessage()
    msg['From'] = cfg['from']
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)

# smtp can raise here
    with smtplib.SMTP(cfg['host'], cfg['port']) as smtp:
        if cfg['starttls']:
            smtp.starttls()

        smtp.login(cfg['username'], cfg['password'])
        smtp.send_message(msg)



def _send_alert(smtp_cfg, client, metrics, _type):
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

    _send_email(smtp_cfg, to, subject.strip(), body)


def check_for_alerts(smtp_cfg, client, metrics):
    """
        Check for alerts and send emails if necessary!
    """
    for _type, _limit in client['alerts'].items():
        if metrics[_type] > _limit:
            _send_alert(smtp_cfg, client, metrics, _type)
