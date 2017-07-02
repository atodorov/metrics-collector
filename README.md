This is a simple client/server application which connects to remote systems
and collects some metrics! Currently CPU usage, memory usage and uptime are
collected. For Windows systems we collect security event logs as well.

# Installing

The server part is designed to work on a Linux system. Using Python 3.5 or newer!
The easiest way is to install inside a python virtualenv:

    $ pip install -r requirements/base.txt
    $ cd src/
    $ python ./server.py ../config.xml


Upon first start `server.py` will create the necessary database schema if
required! This is handled automatically via the SQLAlchemy ORM backend!

When executed `server.py` will connect to each client system via SSH and
upload the `agent.py` script. It will be executed and the response collected
and stored in the database. In the case of client-side errors they will be
reported on the server side and exception will be raised!

If any of the metrics is greater than the configured alerts `server.py` will
send a plain text email to the recipient address.



# Sample configuration XML

```
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <database connection='sqlite:////tmp/collector.db'/>
    <smtp host='smtp.gmail.com' port='587' username='you@gmail.com' password='v3ry-s3cr3t' starttls='yes' />

    <client
        ip='127.0.0.1'
        port='22'
        username='student'
        password='s3cr3t'
        mail="alerts+linux@example.com"
        platform='Linux'>
            <alert type="memory" limit="80%" />
            <alert type="cpu" limit="10%" />
    </client>

    <client
        ip='4.7.8.6'
        username='Administrator'
        password='again-very-secret'
        mail="alerts+windows@example.com"
        platform='Windows'>
            <alert type="memory" limit="30%" />
            <alert type="cpu" limit="10%" />
    </client>

</config>
```

The database connection string is of the form `dialect+driver://username:password@host:port/database`.
You can easily execute a demo using sqlite. In case of MySQL or Postgres you have to
install the necessary driver libraries (MySQL-python or mysqlclient or psycopg2)
For more information see http://docs.sqlalchemy.org/en/latest/core/engines.html

SMTP configuration is self explanatory. The above example works for Gmail and
password authentication.


Currently the following alert types are recognized: `cpu`, `memory`, `uptime`!
They match the metrics collected from `agent.py`.


# Configuring the client systems

A Linux client needs to have OpenSSH running and configured for password
authentication (this is usually the default) and the `psutil` Python package
available in the PYTHONPATH!


A Windows client needs to have OpenSSH up and running. To install follow section
Installing SFTP/SSH Server from https://winscp.net/eng/docs/guide_windows_openssh_server.

Then install Python 3.6.1 from https://www.python.org/downloads/windows/.

Then download the `get-pip.py` script from https://pip.pypa.io/en/stable/installing/
and execute `python get-pip.py`. After pip has been installed execute:

    pip install psutil winevt

