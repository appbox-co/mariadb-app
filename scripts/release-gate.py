#!/usr/bin/env python3
"""Release gate for the MySQL (MariaDB) image. Run on the builder with the
exact built image reference; it exits 0 only when every scenario passes and
the authenticated registry reports the release tag absent.

One MariaDB server container runs at a time, on the default bridge with no
published ports. Clients connect from a separate container, so logins are
remote ones that match '%' hosts, as they would on the published port.

  image    no MYSQL_DATABASE/MYSQL_USER/MYSQL_PASSWORD defaults, the root
           default is unchanged, the server is the tagged version and the
           callback unit test passes.
  fresh    new image on an empty volume: no test account, no test database
           and no anonymous users, root works with the install password,
           the installed callback is sent once, and no password, token or
           shell trace reaches the log. A test@% with another password
           survives a restart; once its password is "test", the next
           restart removes it.
  upgrade  current live image on an empty volume (creates test/test, which
           logs in remotely), customer data and users added, then the new
           image on the same volume: test@% and the empty test database
           are gone; root, the customer user, test@localhost, test2@% and
           the data are intact; one notice line; a restart changes nothing.
  keep     current live image with a table in `test`: after the new image,
           test@% is gone but the test database and its table are kept.
  tls      the released 11.4.13 image with data, then the new image with a
           test CA's certificate chain mounted at /ssl as Appbox mounts it:
           the server sends the chain, it verifies for its hostname and not
           for another, a client with --ssl-verify-server-cert connects, the
           data is intact and a restart serves the same certificate. RSA
           works too. A key that does not match, a key MariaDB cannot read
           and a directory in place of cert.pem each fall back to the
           self-signed certificate and MariaDB still starts.

The image itself must be the 11.4.13 image's layers plus one layer holding
this repository's scripts/run.sh.
"""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location('registry_check', Path(__file__).with_name('registry-check.py'))
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)
if len(sys.argv) != 2 or sys.argv[1] != registry.EXPECTED:
    raise SystemExit('Usage: release-gate.py ' + registry.EXPECTED)
image = sys.argv[1]
version = image.rsplit(':', 1)[1]
# 11.4.13-1 is build revision 1 of MariaDB 11.4.13.
server_version = version.split('-', 1)[0]
repo_root = Path(__file__).resolve().parent.parent
run_id = 'mariadb-release-gate-' + uuid.uuid4().hex[:12]
label = 'appbox.release-gate=' + run_id
containers = []
volumes = []
root_password = secrets.token_hex(16)
app_password = secrets.token_hex(16)
other_password = secrets.token_hex(16)
callback_token = secrets.token_hex(24)
secret_values = (root_password, app_password, other_password, callback_token)
instance_id = '900000074'
callbacks = []
rejected_callbacks = []
NOTICE = "Removed the default test account 'test'@'%'"
NOTICE_DB_DROPPED = '[i] ' + NOTICE + ' and its empty test database'
NOTICE_DB_KEPT = '[i] ' + NOTICE + '; kept the test database because it is not empty'
DEFAULT_HASH = '*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29'
GATE_HOST = 'db.gate.test'
OTHER_HOST = 'other.gate.test'
TLS_SERVING = '[i] Serving the TLS certificate from /ssl ('
TLS_NOT_FILES = '[!] /ssl does not hold both cert.pem and key.pem as files; using a self-signed TLS certificate'
TLS_UNREADABLE = '[!] MariaDB cannot read the TLS certificate or key in /ssl; using a self-signed TLS certificate'
TLS_MISMATCH = ('[!] The TLS certificate and key in /ssl cannot be read or do not match; '
                'using a self-signed TLS certificate')
pki = Path(tempfile.mkdtemp(prefix=run_id + '-pki-'))


def redact(text):
    for value in secret_values:
        text = text.replace(value, '[redacted]')
    return text


def command(args, timeout=300, check=True, env=None):
    p = subprocess.run(args, capture_output=True, timeout=timeout, env=env)
    if check and p.returncode:
        # Never print the arguments or the container environment.
        raise RuntimeError('Builder command failed: ' + redact(p.stderr.decode(errors='replace'))[-1500:])
    return p


class Callback(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        if self.path == '/v1/apps/installed/' + instance_id and \
                self.headers.get('X-Cylo-Callback-Token') == callback_token:
            callbacks.append(time.time())
            self.send_response(200)
        else:
            rejected_callbacks.append(self.path)
            self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


gateway = json.loads(command(['docker', 'network', 'inspect', 'bridge']).stdout)[0]['IPAM']['Config'][0]['Gateway']
callback_server = http.server.ThreadingHTTPServer((gateway, 0), Callback)
threading.Thread(target=callback_server.serve_forever, daemon=True).start()
callback_base = 'http://' + gateway + ':' + str(callback_server.server_port)


def volume(suffix):
    name = run_id + '-' + suffix
    command(['docker', 'volume', 'create', '--label', label, name])
    volumes.append(name)
    return name


def remove_volume(name):
    command(['docker', 'volume', 'rm', name])
    volumes.remove(name)


def start_server(suffix, selected_image, data_volume, callback=False, mounts=()):
    name = run_id + '-' + suffix
    env = dict(os.environ, MYSQL_ROOT_PASSWORD=root_password)
    # volume-nocopy: Appbox bind-mounts an empty host directory, so the
    # image's own /var/lib/mysql must not be copied into the volume.
    args = ['docker', 'run', '-d', '--name', name, '--label', label, '--init',
            '--network', 'bridge',
            '--mount', 'type=volume,src=' + data_volume + ',dst=/var/lib/mysql,volume-nocopy=true',
            '-e', 'MYSQL_ROOT_PASSWORD', '-e', 'PUID=1000', '-e', 'PGID=1000']
    for source, target in mounts:
        args += ['--mount', 'type=bind,src=' + str(source) + ',dst=' + target + ',readonly']
    if callback:
        env['CALLBACK_TOKEN'] = callback_token
        args += ['-e', 'INSTANCE_ID=' + instance_id, '-e', 'CALLBACK_TOKEN',
                 '-e', 'APPBOX_CALLBACK_BASE=' + callback_base]
    args.append(selected_image)
    command(args, env=env)
    containers.append(name)
    return name


def stop_server(name, require_clean=True):
    command(['docker', 'stop', '--time', '180', name], timeout=240)
    code = command(['docker', 'inspect', '--format', '{{.State.ExitCode}}', name]).stdout.decode().strip()
    if require_clean:
        assert code == '0', 'Server did not shut down cleanly (exit ' + code + ')'
    command(['docker', 'rm', name])
    containers.remove(name)


def restart_server(name):
    command(['docker', 'restart', '--time', '180', name], timeout=240)


def server_ip(name):
    ip = command(['docker', 'inspect', '--format', '{{(index .NetworkSettings.Networks "bridge").IPAddress}}',
                  name]).stdout.decode().strip()
    assert ip, 'Server has no bridge address'
    return ip


def start_client():
    # One long-lived client container (it only sleeps; no server runs in it),
    # so each query is a cheap `docker exec` instead of a new container.
    name = run_id + '-client'
    command(['docker', 'run', '-d', '--name', name, '--label', label, '--network', 'bridge',
             '--entrypoint', 'sleep', image, 'infinity'])
    containers.append(name)
    return name


def sql(name, user, password, statement, check=True):
    env = dict(os.environ, MYSQL_PWD=password)
    p = command(['docker', 'exec', '-e', 'MYSQL_PWD', client, 'mariadb', '--no-defaults', '--protocol=tcp',
                 '-h', server_ip(name), '-P', '3306', '-u', user, '--connect-timeout=10',
                 '--batch', '--skip-column-names', '-e', statement],
                timeout=300, check=False, env=env)
    if check and p.returncode:
        raise RuntimeError('SQL as ' + user + ' failed: ' + redact(p.stderr.decode(errors='replace'))[-800:])
    return p


def query(name, statement):
    return sql(name, 'root', root_password, statement).stdout.decode().strip()


def logs(name):
    p = command(['docker', 'logs', name])
    return (p.stdout + p.stderr).decode(errors='replace')


def wait_ready(name, timeout=900):
    started = time.monotonic()
    last = ''
    while time.monotonic() - started < timeout:
        running = command(['docker', 'inspect', '--format', '{{.State.Running}}', name]).stdout.decode().strip()
        if running != 'true':
            last = 'container stopped'
            break
        try:
            p = sql(name, 'root', root_password, 'SELECT VERSION()', check=False)
        except subprocess.TimeoutExpired:
            last = 'client timed out'
            continue
        if p.returncode == 0:
            return p.stdout.decode().strip(), round(time.monotonic() - started)
        last = redact(p.stderr.decode(errors='replace')).strip()[-300:]
        time.sleep(3)
    tail = '\n'.join(line for line in redact(logs(name)).splitlines()[-60:]
                     if 'password' not in line.lower())
    print(tail, flush=True)
    raise RuntimeError('Server not ready: ' + last)


def wait_callbacks(count, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(callbacks) < count:
        time.sleep(1)
    time.sleep(3)
    assert len(callbacks) == count, 'Expected %d installed callbacks, got %d' % (count, len(callbacks))
    assert not rejected_callbacks, 'Callback with a wrong path or token'


def test_login_refused(name):
    p = sql(name, 'test', 'test', 'SELECT CURRENT_USER()', check=False)
    # 1045, or 1698 when another 'test' account exists for a different host;
    # both are SQLSTATE 28000 access denied.
    if p.returncode == 0 or not re.search(rb'ERROR (1045|1698) \(28000\): Access denied', p.stderr):
        script_lines = [line for line in redact(logs(name)).splitlines() if line.startswith(('[i]', '[!]'))]
        print('\n'.join(script_lines[-40:]), flush=True)
        raise AssertionError('test/test login was not refused (exit %d, output %r, error %r)' % (
            p.returncode, p.stdout.decode(errors='replace').strip(), redact(p.stderr.decode(errors='replace')).strip()))


def count(name, statement):
    return int(query(name, statement))


def test_user_count(name):
    return count(name, "SELECT COUNT(*) FROM mysql.global_priv WHERE User = 'test' AND Host = '%'")


def test_db_count(name):
    return count(name, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'test'")


def check_log(name, notices):
    text = logs(name)
    for value in secret_values:
        assert value not in text, 'A password or token reached the container log'
    assert not any(line.startswith('+ ') for line in text.splitlines()), 'Shell trace in the container log'
    assert 'with password' not in text, 'Password message in the container log'
    found = [line for line in text.splitlines() if NOTICE in line]
    assert found == notices, 'Unexpected test-account notices: %r' % found


def users(name):
    return query(name, "SELECT CONCAT(User, '@', Host) FROM mysql.global_priv ORDER BY 1").splitlines()


def openssl(*args):
    return command(['openssl', *[str(a) for a in args]], timeout=120)


def make_pki():
    """A root CA, an intermediate and two leaves for GATE_HOST (EC P-384, as
    acme.sh issues, and RSA 2048), each cert file holding leaf + intermediate
    the way acme.sh's fullchain does. Clients trust only the root, so a
    verified handshake proves the server sends the chain."""
    def key(name, kind):
        if kind == 'ec':
            openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384', '-out', pki / name)
        else:
            openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', pki / name)

    def ext(name, text):
        (pki / name).write_text(text)
        return pki / name

    key('root.key', 'ec')
    openssl('req', '-x509', '-new', '-key', pki / 'root.key', '-out', pki / 'root.pem', '-days', '7',
            '-subj', '/CN=MariaDB release gate root', '-addext', 'basicConstraints=critical,CA:true',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    key('int.key', 'ec')
    openssl('req', '-new', '-key', pki / 'int.key', '-out', pki / 'int.csr',
            '-subj', '/CN=MariaDB release gate intermediate')
    openssl('x509', '-req', '-in', pki / 'int.csr', '-CA', pki / 'root.pem', '-CAkey', pki / 'root.key',
            '-set_serial', '2', '-days', '7', '-out', pki / 'int.pem',
            '-extfile', ext('int.ext', 'basicConstraints=critical,CA:true,pathlen:0\n'
                                       'keyUsage=critical,keyCertSign,cRLSign\n'))
    leaf_ext = ext('leaf.ext', 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n'
                               'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + GATE_HOST + '\n')
    for kind, serial in (('ec', '3'), ('rsa', '4')):
        key(kind + '.key', kind)
        openssl('req', '-new', '-key', pki / (kind + '.key'), '-out', pki / (kind + '.csr'), '-subj', '/CN=' + GATE_HOST)
        openssl('x509', '-req', '-in', pki / (kind + '.csr'), '-CA', pki / 'int.pem', '-CAkey', pki / 'int.key',
                '-set_serial', serial, '-days', '7', '-out', pki / (kind + '-leaf.pem'), '-extfile', leaf_ext)
        (pki / (kind + '-cert.pem')).write_bytes((pki / (kind + '-leaf.pem')).read_bytes() +
                                                 (pki / 'int.pem').read_bytes())
    key('other.key', 'ec')
    # acme.sh leaves cert and key 0644 for the apps that mount them.
    for path in pki.iterdir():
        path.chmod(0o644)
    pki.chmod(0o755)
    shutil.copyfile(pki / 'ec.key', pki / 'private.key')
    (pki / 'private.key').chmod(0o600)
    # Docker makes a directory when a bind source is missing.
    (pki / 'missing.crt').mkdir(mode=0o755)


def tls_mounts(cert, key):
    return ((pki / cert, '/ssl/cert.pem'), (pki / key, '/ssl/key.pem'))


def tls_handshake(ip, hostname=None):
    args = ['openssl', 's_client', '-starttls', 'mysql', '-connect', ip + ':3306', '-showcerts']
    if hostname:
        args += ['-servername', hostname, '-verify_hostname', hostname, '-verify_return_error',
                 '-CAfile', str(pki / 'root.pem')]
    return subprocess.run(args, input=b'', capture_output=True, timeout=60)


def verified(ip, hostname):
    p = tls_handshake(ip, hostname)
    return p.returncode == 0 and b'Verify return code: 0 (ok)' in p.stdout


def served_certificate(ip):
    p = tls_handshake(ip)
    assert b'BEGIN CERTIFICATE' in p.stdout, 'No certificate in the TLS handshake'
    out = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-fingerprint', '-sha256'],
                         input=p.stdout, capture_output=True, timeout=60).stdout.decode()
    subject = next(line for line in out.splitlines() if line.startswith('subject'))
    fingerprint = next(line for line in out.splitlines() if 'Fingerprint' in line)
    return subject, fingerprint


def is_self_signed(subject):
    return subject.replace(' ', '') == 'subject=CN=MariaDBServer'


def verified_client_session(name):
    """mariadb with --ssl-verify-server-cert against GATE_HOST, trusting only
    the gate root, from a client that resolves GATE_HOST to the server."""
    client_name = run_id + '-tlsclient'
    command(['docker', 'run', '-d', '--name', client_name, '--label', label, '--network', 'bridge',
             '--add-host', GATE_HOST + ':' + server_ip(name),
             '--mount', 'type=bind,src=' + str(pki / 'root.pem') + ',dst=/gate-root.pem,readonly',
             '--entrypoint', 'sleep', image, 'infinity'])
    containers.append(client_name)
    try:
        env = dict(os.environ, MYSQL_PWD=root_password)
        p = command(['docker', 'exec', '-e', 'MYSQL_PWD', client_name, 'mariadb', '--no-defaults', '--protocol=tcp',
                     '-h', GATE_HOST, '-P', '3306', '-u', 'root', '--connect-timeout=10', '--ssl',
                     '--ssl-ca=/gate-root.pem', '--ssl-verify-server-cert', '--batch', '--skip-column-names',
                     '-e', "SHOW SESSION STATUS LIKE 'Ssl_version'"], check=False, env=env)
        if p.returncode:
            raise AssertionError('Verified client session failed: ' + redact(p.stderr.decode(errors='replace'))[-600:])
        return p.stdout.decode().split()[-1]
    finally:
        command(['docker', 'rm', '-f', client_name])
        containers.remove(client_name)


def tls_notices(name):
    return [line for line in logs(name).splitlines()
            if line.startswith(('[i] Serving the TLS', '[!] /ssl', '[!] MariaDB cannot read', '[!] The TLS'))]


def check_image():
    # The unit test allows the app 2s to start; a busy builder can miss that
    # once, so a failure is retried one time before it fails the gate.
    for attempt in (1, 2):
        unit = subprocess.run(['bash', str(repo_root / 'tests' / 'test-installed-callback.sh')],
                              capture_output=True, timeout=600)
        if unit.returncode == 0:
            break
        print(unit.stdout.decode(errors='replace')[-3000:], flush=True)
        if attempt == 2:
            raise RuntimeError('tests/test-installed-callback.sh failed twice')
        print('Callback unit test failed once; retrying', flush=True)
    print('PASS callback unit test', flush=True)
    details = json.loads(command(['docker', 'image', 'inspect', image]).stdout)[0]
    assert details['Architecture'] == 'amd64' and details['Os'] == 'linux'
    env = dict(item.split('=', 1) for item in details['Config']['Env'])
    assert not {'MYSQL_DATABASE', 'MYSQL_USER', 'MYSQL_PASSWORD'} & env.keys(), 'Test defaults still in the image'
    assert env.get('MYSQL_ROOT_PASSWORD') == 'mysqlr00t', 'Root password default changed'
    out = command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'sh', image, '-c',
                   'mariadbd --version; /opt/mariadb/10.6/bin/mariadbd --version; '
                   '/opt/mariadb/10.11/bin/mariadbd --version; test -x /usr/local/bin/appbox-installed-callback'
                   ]).stdout.decode()
    assert 'Ver ' + server_version + '-MariaDB' in out, 'Server is not MariaDB ' + server_version
    assert 'Ver 10.6.' in out and 'Ver 10.11.' in out, 'Upgrade binaries missing'
    print('PASS image: no test defaults, root default unchanged, MariaDB', server_version,
          'with 10.6/10.11 upgrade binaries', flush=True)

    # The released 11.4.13 image unchanged, plus one layer with run.sh.
    command(['docker', 'pull', '--quiet', registry.PREVIOUS], timeout=900)
    base_layers = json.loads(command(['docker', 'image', 'inspect', registry.PREVIOUS]).stdout)[0]['RootFS']['Layers']
    layers = details['RootFS']['Layers']
    assert layers[:len(base_layers)] == base_layers and len(layers) == len(base_layers) + 1, \
        'Image is not the 11.4.13 image plus one layer'
    shipped = command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', image,
                       '/scripts/run.sh']).stdout
    assert shipped == (repo_root / 'scripts' / 'run.sh').read_bytes(), 'Image run.sh differs from the repository'
    mode = command(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'stat', image,
                    '-c', '%a %U', '/scripts/run.sh']).stdout.decode().strip()
    assert mode == '755 root', 'run.sh mode/owner is ' + mode
    print('PASS image layers: the 11.4.13 image plus one layer holding this run.sh (755 root)', flush=True)


def scenario_fresh():
    data = volume('fresh')
    sent = len(callbacks)
    fresh = start_server('fresh', image, data, callback=True)
    found, seconds = wait_ready(fresh)
    assert found.startswith(server_version + '-MariaDB'), found
    test_login_refused(fresh)
    assert test_user_count(fresh) == 0 and test_db_count(fresh) == 0
    assert count(fresh, "SELECT COUNT(*) FROM mysql.global_priv WHERE User = ''") == 0, 'Anonymous users present'
    assert users(fresh) == ['mariadb.sys@localhost', 'mysql@localhost', 'root@%', 'root@localhost'], users(fresh)
    wait_callbacks(sent + 1)
    check_log(fresh, [])
    subject, _ = served_certificate(server_ip(fresh))
    assert is_self_signed(subject), 'Without /ssl the server serves ' + subject
    assert not any(line.startswith(('[i] Serving the TLS', '[!] /ssl', '[!] MariaDB cannot read', '[!] The TLS'))
                   for line in logs(fresh).splitlines()), 'TLS notice without /ssl'
    print('PASS fresh install: ready in %ss; no test account, test database or anonymous user; root works; '
          'one callback; no secrets or trace in the log; without /ssl the self-signed certificate as before'
          % seconds, flush=True)

    query(fresh, "CREATE USER 'test'@'%' IDENTIFIED BY '" + other_password + "'; CREATE DATABASE `test`")
    restart_server(fresh)
    wait_ready(fresh)
    assert test_user_count(fresh) == 1 and test_db_count(fresh) == 1, 'Non-default test account was touched'
    check_log(fresh, [])
    query(fresh, "ALTER USER 'test'@'%' IDENTIFIED BY 'test'")
    assert sql(fresh, 'test', 'test', 'SELECT 1', check=False).returncode == 0, 'Control login failed'
    restart_server(fresh)
    wait_ready(fresh)
    test_login_refused(fresh)
    assert test_user_count(fresh) == 0 and test_db_count(fresh) == 0
    wait_callbacks(sent + 1)
    check_log(fresh, [NOTICE_DB_DROPPED])
    stop_server(fresh)
    remove_volume(data)
    print('PASS restart: a test@% with another password is kept; with the password "test" it and the empty '
          'test database are removed on the next start; no further callback', flush=True)


def scenario_upgrade():
    data = volume('upgrade')
    base = start_server('upgrade-current', registry.CURRENT, data)
    found, seconds = wait_ready(base)
    p = sql(base, 'test', 'test', 'SELECT CURRENT_USER()')
    assert p.stdout.decode().strip() == 'test@%', 'Baseline test login did not reproduce'
    assert query(base, "SELECT JSON_VALUE(Priv, '$.authentication_string') FROM mysql.global_priv "
                       "WHERE User = 'test' AND Host = '%'") == DEFAULT_HASH
    query(base, "CREATE DATABASE appdb; "
                "CREATE TABLE appdb.items (id INT PRIMARY KEY, label VARCHAR(64)) ENGINE=InnoDB; "
                "INSERT INTO appdb.items VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma'); "
                "CREATE USER 'appuser'@'%' IDENTIFIED BY '" + app_password + "'; "
                "GRANT ALL ON appdb.* TO 'appuser'@'%'; "
                "CREATE USER 'test'@'localhost' IDENTIFIED BY 'test'; "
                "CREATE USER 'test2'@'%' IDENTIFIED BY 'test'")
    checksum = query(base, 'CHECKSUM TABLE appdb.items')
    users_before = users(base)
    stop_server(base, require_clean=False)
    print('PASS baseline %s (ready in %ss): test/test logs in remotely as test@%%; customer data added'
          % (found, seconds), flush=True)

    sent = len(callbacks)
    upgraded = start_server('upgrade-new', image, data, callback=True)
    found, seconds = wait_ready(upgraded)
    assert found.startswith(server_version + '-MariaDB'), found
    test_login_refused(upgraded)
    assert test_user_count(upgraded) == 0 and test_db_count(upgraded) == 0
    assert users(upgraded) == [u for u in users_before if u != 'test@%'], users(upgraded)
    assert query(upgraded, "SELECT JSON_VALUE(Priv, '$.authentication_string') FROM mysql.global_priv "
                           "WHERE User = 'test2' AND Host = '%'") == DEFAULT_HASH, 'test2@% changed'
    assert query(upgraded, 'CHECKSUM TABLE appdb.items') == checksum, 'Customer data changed'
    assert sql(upgraded, 'appuser', app_password, 'SELECT COUNT(*) FROM appdb.items').stdout.decode().strip() == '3'
    assert query(upgraded, 'SELECT 1') == '1'
    wait_callbacks(sent + 1)
    check_log(upgraded, [NOTICE_DB_DROPPED])
    print('PASS upgrade from the current image: ready in %ss; test@%% and the empty test database removed; root, '
          'appuser, test@localhost, test2@%% and appdb intact; one notice; callback sent' % seconds, flush=True)

    restart_server(upgraded)
    wait_ready(upgraded)
    assert query(upgraded, 'CHECKSUM TABLE appdb.items') == checksum
    assert users(upgraded) == [u for u in users_before if u != 'test@%']
    wait_callbacks(sent + 1)
    check_log(upgraded, [NOTICE_DB_DROPPED])
    stop_server(upgraded)
    remove_volume(data)
    print('PASS restart after upgrade: nothing else removed, data intact, no notice or callback', flush=True)


def scenario_keep():
    data = volume('keep')
    base = start_server('keep-current', registry.CURRENT, data)
    wait_ready(base)
    query(base, "CREATE TABLE test.keepme (id INT PRIMARY KEY, note VARCHAR(64)); "
                "INSERT INTO test.keepme VALUES (1, 'keep')")
    stop_server(base, require_clean=False)
    kept = start_server('keep-new', image, data)
    wait_ready(kept)
    test_login_refused(kept)
    assert test_user_count(kept) == 0, 'test@% not removed'
    assert test_db_count(kept) == 1 and query(kept, 'SELECT note FROM test.keepme') == 'keep', 'test data lost'
    check_log(kept, [NOTICE_DB_KEPT])
    stop_server(kept)
    remove_volume(data)
    print('PASS test database with a table: test@% removed, test database and table kept', flush=True)


def scenario_tls():
    make_pki()
    data = volume('tls')
    base = start_server('tls-previous', registry.PREVIOUS, data)
    found, _ = wait_ready(base)
    assert found.startswith(server_version + '-MariaDB'), found
    query(base, "CREATE DATABASE tlsdb; "
                "CREATE TABLE tlsdb.items (id INT PRIMARY KEY, label VARCHAR(64)) ENGINE=InnoDB; "
                "INSERT INTO tlsdb.items VALUES (1, 'alpha'), (2, 'beta')")
    checksum = query(base, 'CHECKSUM TABLE tlsdb.items')
    subject, _ = served_certificate(server_ip(base))
    assert is_self_signed(subject), 'Baseline serves ' + subject
    stop_server(base, require_clean=False)
    print('PASS baseline 11.4.13 with data serves the self-signed certificate', flush=True)

    server = start_server('tls-ec', image, data, mounts=tls_mounts('ec-cert.pem', 'ec.key'))
    found, seconds = wait_ready(server)
    assert found.startswith(server_version + '-MariaDB'), found
    ip = server_ip(server)
    assert query(server, 'CHECKSUM TABLE tlsdb.items') == checksum, 'Data changed'
    assert verified(ip, GATE_HOST), 'Handshake does not verify for ' + GATE_HOST + ' against the root alone'
    assert not verified(ip, OTHER_HOST), 'Handshake verified for a hostname the certificate does not name'
    subject, fingerprint = served_certificate(ip)
    assert GATE_HOST in subject, subject
    tls_version = verified_client_session(server)
    assert tls_version.startswith('TLSv1.'), tls_version
    notices = tls_notices(server)
    assert len(notices) == 1 and notices[0].startswith(TLS_SERVING) and GATE_HOST in notices[0], notices
    assert 'PRIVATE KEY' not in logs(server), 'Key material in the log'
    check_log(server, [])
    print('PASS 11.4.13 -> new image with an EC chain in /ssl: ready in %ss, data intact, chain sent, verifies for %s '
          'and not for %s, mariadb --ssl-verify-server-cert connects over %s, one notice'
          % (seconds, GATE_HOST, OTHER_HOST, tls_version), flush=True)

    restart_server(server)
    wait_ready(server)
    assert served_certificate(server_ip(server))[1] == fingerprint, 'Certificate changed across a restart'
    stop_server(server)
    print('PASS restart serves the same certificate', flush=True)

    server = start_server('tls-rsa', image, data, mounts=tls_mounts('rsa-cert.pem', 'rsa.key'))
    wait_ready(server)
    assert verified(server_ip(server), GATE_HOST), 'RSA certificate does not verify'
    stop_server(server)
    print('PASS RSA certificate verifies', flush=True)

    for suffix, mounts, notice in (
            ('tls-mismatch', tls_mounts('ec-cert.pem', 'other.key'), TLS_MISMATCH),
            ('tls-unreadable', tls_mounts('ec-cert.pem', 'private.key'), TLS_UNREADABLE),
            ('tls-directory', tls_mounts('missing.crt', 'ec.key'), TLS_NOT_FILES)):
        server = start_server(suffix, image, data, mounts=mounts)
        wait_ready(server)
        subject, _ = served_certificate(server_ip(server))
        assert is_self_signed(subject), suffix + ' serves ' + subject
        assert tls_notices(server) == [notice], tls_notices(server)
        assert query(server, 'CHECKSUM TABLE tlsdb.items') == checksum, 'Data changed'
        stop_server(server)
        print('PASS ' + suffix + ': MariaDB starts with the self-signed certificate and says why', flush=True)
    remove_volume(data)


try:
    aio_used = int(Path('/proc/sys/fs/aio-nr').read_text())
    aio_max = int(Path('/proc/sys/fs/aio-max-nr').read_text())
    if aio_max - aio_used < 20000:
        raise RuntimeError('Not enough free AIO contexts on the builder (%d of %d used)' % (aio_used, aio_max))
    check_image()
    client = start_client()
    scenario_fresh()
    scenario_upgrade()
    scenario_keep()
    scenario_tls()
except Exception as error:
    print('FAIL release gate: ' + type(error).__name__ + ': ' + redact(str(error)), flush=True)
    raise
finally:
    for name in list(reversed(containers)):
        try:
            found = command(['docker', 'inspect', '--format', '{{index .Config.Labels "appbox.release-gate"}}',
                             name]).stdout.decode().strip()
            if found != run_id:
                raise RuntimeError('Container cleanup identity mismatch')
            command(['docker', 'rm', '-f', name])
        except Exception as error:
            print('Cleanup requires attention:', name, type(error).__name__, flush=True)
    for name in list(volumes):
        try:
            found = command(['docker', 'volume', 'inspect', '--format', '{{index .Labels "appbox.release-gate"}}',
                             name]).stdout.decode().strip()
            if found != run_id:
                raise RuntimeError('Volume cleanup identity mismatch')
            command(['docker', 'volume', 'rm', name])
        except Exception as error:
            print('Cleanup requires attention:', name, type(error).__name__, flush=True)
    callback_server.shutdown()
    shutil.rmtree(pki, ignore_errors=True)

registry.require_absent(image)
print('PASS all release gates for', image, flush=True)
