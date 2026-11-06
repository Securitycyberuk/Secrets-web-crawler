"""Local, scope-limited QR exposure review tool."""
import ipaddress
import base64
import binascii
import os
import sqlite3
import hashlib
import hmac
import email.utils
from contextlib import closing
import shutil
import json
import re
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.robotparser
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

ROOT = Path(__file__).parent
JOBS = {}
LOCK = threading.Lock()
HEADERS = {"User-Agent": "QRExposureReview/1.0 (authorized security assessment)"}
MAX_BYTES = 5_000_000
DATA_DIR = ROOT / 'data'
DB_PATH = DATA_DIR / 'scans.sqlite3'
DB_LOCK = threading.Lock()

def init_store():
    DATA_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(DATA_DIR, 0o700)
    fd = os.open(DB_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    os.chmod(DB_PATH, 0o600)
    with closing(sqlite3.connect(DB_PATH)) as db, db:
        db.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, data TEXT NOT NULL)')
        for job_id, raw in db.execute('SELECT id, data FROM jobs'):
            job = json.loads(raw)
            if job.get('status') == 'running':
                job['status'] = 'interrupted'
                job.setdefault('warnings', []).append('Server stopped during the scan. Results are retained; the crawl cannot resume automatically.')
                job['current_url'] = None
            JOBS[job_id] = job
        for job in JOBS.values():
            db.execute('UPDATE jobs SET data=? WHERE id=?', (json.dumps(job), job['id']))

def save_job(job):
    if 'id' not in job: return
    with DB_LOCK, closing(sqlite3.connect(DB_PATH)) as db, db:
        db.execute('INSERT OR REPLACE INTO jobs (id, data) VALUES (?, ?)', (job['id'], json.dumps(job)))



def safe_url(url, origin=None):
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Enter a valid HTTP(S) URL without credentials.")
    if origin and (p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)) != origin:
        raise ValueError("URL is outside the selected origin.")
    try:
        addresses = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == 'https' else 80), type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError("Only public internet addresses are allowed.")
    except socket.gaierror as exc:
        raise ValueError("Host could not be resolved.") from exc
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))


def sanitized(url):
    p = urllib.parse.urlsplit(url)
    # Paths can contain tokens, too; retain only the origin in stored evidence.
    return urllib.parse.urlunsplit((p.scheme, p.netloc, '', '', ''))


def report_location(url):
    p = urllib.parse.urlsplit(url)
    segments = []
    for part in p.path.split('/'):
        decoded = urllib.parse.unquote(part)
        # Hide long opaque path components, which often contain tokens or keys.
        segments.append('[redacted]' if len(decoded) >= 32 and re.fullmatch(r'[A-Za-z0-9_~+%=-]+', decoded) else part)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, '/'.join(segments), '', ''))


def fetch(url, origin, max_bytes=MAX_BYTES):
    # Redirects are checked explicitly before any follow-up request.
    for _ in range(4):
        url = safe_url(url, origin)
        with requests.get(url, headers=HEADERS, timeout=(5, 12), stream=True, allow_redirects=False) as response:
            if response.is_redirect:
                url = urllib.parse.urljoin(url, response.headers.get('Location', ''))
                continue
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_content(65536):
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise ValueError('Response exceeded size limit')
            return url, response.headers.get('Content-Type', '').lower(), bytes(data)
    raise ValueError('Too many redirects')


class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self.images = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a' and a.get('href'): self.links.append(a['href'])
        if tag == 'img' and a.get('src'): self.images.append(a['src'])
        if tag == 'script' and a.get('src'): self.links.append(a['src'])
        if tag == 'link' and a.get('href') and any(x in a.get('rel', '').lower().split() for x in ('stylesheet', 'preload', 'modulepreload')): self.links.append(a['href'])


def valid_bitcoin_address(value):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if value.startswith(('1', '3')):
        if not 26 <= len(value) <= 35 or any(c not in alphabet for c in value): return False
        number = 0
        for c in value: number = number * 58 + alphabet.index(c)
        raw = b'\x00' * (len(value) - len(value.lstrip('1'))) + number.to_bytes((number.bit_length() + 7) // 8, 'big')
        return len(raw) == 25 and raw[0] in (0, 5) and hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]
    # Bech32 and Bech32m checksum plus witness-version and program constraints.
    if value.lower() != value and value.upper() != value: return False
    value = value.lower()
    if not value.startswith('bc1') or not 14 <= len(value) <= 90: return False
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    try: data = [charset.index(c) for c in value[3:]]
    except ValueError: return False
    if len(data) < 7: return False
    chk = 1
    for item in [ord(c) >> 5 for c in 'bc'] + [0] + [ord(c) & 31 for c in 'bc'] + data:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ item
        for i, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> i) & 1: chk ^= generator
    version = data[0]
    if version > 16 or chk != (1 if version == 0 else 0x2bc830a3): return False
    acc = bits = 0
    program = []
    for part in data[1:-6]:
        acc = (acc << 5) | part
        bits += 5
        while bits >= 8:
            bits -= 8
            program.append((acc >> bits) & 255)
    if bits >= 5 or (acc << (8 - bits)) & 255: return False
    return 2 <= len(program) <= 40 and (version != 0 or len(program) in (20, 32))

def keccak256(data):
    # Keccak-256 (Ethereum), not the different SHA3-256 padding.
    rc = (0x0000000000000001,0x0000000000008082,0x800000000000808a,0x8000000080008000,0x000000000000808b,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008a,0x0000000000000088,0x0000000080008009,0x000000008000000a,0x000000008000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800a,0x800000008000000a,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008)
    rotations = ((0,36,3,41,18),(1,44,10,45,2),(62,6,43,15,61),(28,55,25,21,56),(27,20,39,8,14))
    mask = (1 << 64) - 1
    state = [0] * 25
    padded = bytearray(data); padded.append(1)
    padded.extend(b'\0' * ((-len(padded)-1) % 136)); padded.append(128)
    for off in range(0,len(padded),136):
        block=padded[off:off+136]
        for i in range(17): state[i] ^= int.from_bytes(block[8*i:8*i+8], 'little')
        for constant in rc:
            c=[state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20] for x in range(5)]
            d=[c[(x-1)%5]^(((c[(x+1)%5]<<1)|(c[(x+1)%5]>>63))&mask) for x in range(5)]
            for x in range(5):
                for y in range(5): state[x+5*y] ^= d[x]
            b=[0]*25
            for x in range(5):
                for y in range(5):
                    v=state[x+5*y]; r=rotations[x][y]
                    b[y+5*((2*x+3*y)%5)] = ((v<<r)|(v>>(64-r if r else 64)))&mask
            for x in range(5):
                for y in range(5): state[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y])
            state[0] ^= constant
    return b''.join(v.to_bytes(8,'little') for v in state)[:32]

def ethereum_address_status(value):
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}', value): return 'invalid format'
    body=value[2:]
    if body == body.lower() or body == body.upper(): return 'unchecksummed format'
    digest=keccak256(body.lower().encode('ascii')).hex()
    return 'checksum valid' if all(not c.isalpha() or c.isupper()==(int(digest[i],16)>=8) for i,c in enumerate(body)) else 'checksum mismatch'

def classify(payload):
    s = payload.strip()
    lower = s.lower()
    if re.match(r'^(bitcoin|ethereum|litecoin|bitcoincash|dogecoin|solana):', lower):
        return 'Payment URI', 'informational', 'A payment URI is usually intended to be shared; review context before treating it as an exposure.'
    if valid_bitcoin_address(s):
        return 'Public wallet address', 'informational', 'Bitcoin address passed a checksum check. This does not prove ownership or use.'
    if re.fullmatch(r'0x[a-fA-F0-9]{40}', s):
        status = ethereum_address_status(s)
        return 'Public wallet address', 'informational' if status != 'checksum mismatch' else 'review', 'Ethereum-style address: '+status+'. This does not establish ownership, activity, or which EVM network it belongs to.'
    if re.fullmatch(r'(?:[a-z]+\s+){11,23}[a-z]+', lower) and len(s.split()) in (12, 15, 18, 21, 24):
        return 'Possible recovery phrase', 'high', 'Possible recovery phrase; validate privately and treat as compromised if confirmed.'
    if re.fullmatch(r'(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})', s):
        if validate_local(s)['status'] != 'checksum valid': return None
        return 'Possible private key', 'high', 'Bitcoin WIF checksum and key range pass; this does not prove ownership or use.'
    if re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', s):
        return 'Possible private key', 'high', 'A 64-character hexadecimal string can also be a hash; verify context privately.'
    return None



# Scan distinctive strings. A bare 64-digit hex
# string is intentionally not scanned in page text: hashes are ubiquitous.
TEXT_PATTERNS = [
    re.compile(r"(?<![A-Za-z0-9])(?:bitcoin|ethereum|litecoin|bitcoincash|dogecoin|solana):[^\s\"'<>]+", re.I),
    re.compile(r"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{11,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})(?![A-Za-z0-9])", re.I),
    re.compile(r"(?<![A-Za-z0-9])(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})(?![A-Za-z0-9])"),
    re.compile(r"(?i)(?:private[ _-]?key|seed[ _-]?phrase|recovery[ _-]?phrase)\s*[=:]\s*[\"']?((?:0x)?[a-f0-9]{64}|(?:[a-z]+\s+){11,23}[a-z]+)"),
]

SECRET_RULES = [
    ('Azure storage account key', re.compile(r'(?i)\bAccountKey\s*=\s*([A-Za-z0-9+/]{86}==)(?![A-Za-z0-9+/=])')),
    ('Azure client secret', re.compile(r'(?i)[\"\']?AZURE_CLIENT_SECRET[\"\']?\s*[:=]\s*[\"\']?([^\"\'\s;]{6,512})')),
    ('AWS secret access key', re.compile(r'(?i)[\"\']?aws[_-]?secret[_-]?access[_-]?key[\"\']?\s*[:=]\s*[\"\']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])')),
    ('AWS access key ID', re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])')),
    ('GitHub token', re.compile(r'(?<![A-Za-z0-9_])(?:ghs_[A-Za-z0-9]+_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})(?![A-Za-z0-9_])')),
    ('Slack token', re.compile(r'(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,200}')),
    ('Google API key', re.compile(r'(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])')),
    ('Stripe secret key', re.compile(r'(?<![A-Za-z0-9_])(?:sk_live|rk_live)_[A-Za-z0-9]{16,255}(?![A-Za-z0-9_])')),
    ('GitLab token', re.compile(r'(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])')),
    ('OpenAI-style API key', re.compile(r'(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])')),
    ('Bearer token', re.compile(r'(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{20,2048})')),
    ('Possible unquoted credential', re.compile(r'(?im)^[ \t]*(?:export[ \t]+)?(?:[A-Za-z0-9_]*(?:API_KEY|API_SECRET|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|PASSWORD|PASSWD|SECRET_KEY))[ \t]*=[ \t]*([^\s\"\'#;]{6,512})[ \t]*(?:\#.*)?$')),

    ('Private key block', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{1,30000}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----')),
    ('Possible credential', re.compile(r"(?i)(?:[\"']?(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret[_-]?key)[\"']?)\s*[:=]\s*[\"']([^\"'\r\n]{6,512})[\"']")),
]

def secret_matches(text):
    matches = []
    for name, pattern in SECRET_RULES:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if value.lower() in {'password', 'changeme', 'example', 'your-api-key', 'your_api_key', 'placeholder', 'redacted', '********'} or '${' in value or '{{' in value:
                continue
            matches.append((name, value))
    specific = {value for name, value in matches if name not in ('Possible credential', 'Possible unquoted credential')}
    seen = set()
    for name, value in matches:
        if name in ('Possible credential', 'Possible unquoted credential') and value in specific: continue
        if (name, value) in seen: continue
        seen.add((name, value))
        if name == 'AWS access key ID':
            yield (name, 'review', 'AWS access-key ID is an identifier; validation requires its matching secret and any session token.'), value
        elif name == 'GitHub token':
            yield (name, 'high', 'GitHub token prefix and character pattern match only; authenticity, activity, and ownership are unverified. Examples and test data may match.'), value
        else:
            yield (name, 'high', 'Pattern match only, not a verified credential. Examples and placeholders may match. Verify privately, then rotate confirmed credentials.'), value

AZURE_URL_PATTERN = re.compile(r'https://[a-zA-Z0-9][a-zA-Z0-9.-]*\.(?:blob\.core\.windows\.net|file\.core\.windows\.net|queue\.core\.windows\.net|table\.core\.windows\.net|vault\.azure\.net|openai\.azure\.com|azurewebsites\.net)(?::443)?(?:/[^\s\"\'<>]*)?', re.I)

def azure_resource_matches(text):
    for match in AZURE_URL_PATTERN.finditer(text):
        url = match.group(0).rstrip('.,;)]}')
        yield ('Azure resource URL', 'informational', 'Azure service endpoint referenced by this resource; its presence does not establish public access or exposure.'), url

def text_matches(text):
    seen = set()
    for pattern in TEXT_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            result = classify(value)
            if result and (result[0], value) not in seen:
                seen.add((result[0], value))
                yield result, value

def validate_local(value):
    value = value.strip()
    if re.fullmatch(r'(?:AKIA|ASIA)[A-Z0-9]{16}', value):
        return {'status':'format match', 'detail':'AWS access-key ID format only; this is not proof of a working credential.'}
    if re.fullmatch(r'0x[0-9a-fA-F]{40}', value):
        return {'status':ethereum_address_status(value), 'detail':'EIP-55 is checked for mixed-case addresses; ownership and network are not verified.'}
    if re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', value):
        n = int(value.removeprefix('0x'), 16)
        valid = 0 < n < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return {'status':'format match' if valid else 'invalid format', 'detail':'The value is within the secp256k1 private-key range.' if valid else 'The value is outside the secp256k1 private-key range. This does not establish whether the value is a key.'}
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if value and all(c in alphabet for c in value) and len(value) in (51,52):
        number = 0
        for c in value: number = number * 58 + alphabet.index(c)
        raw = number.to_bytes((number.bit_length()+7)//8, 'big')
        raw = b'\x00'*(len(value)-len(value.lstrip('1'))) + raw
        checksum = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
        valid = len(raw) in (37,38) and raw[0]==128 and checksum==raw[-4:] and (len(raw)==37 or raw[-5]==1) and 0 < int.from_bytes(raw[1:33], 'big') < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        return {'status':'checksum valid' if valid else 'invalid format', 'detail':'Bitcoin WIF checksum and key range checked locally; ownership and funds were not checked.'}
    return {'status':'unsupported', 'detail':'No offline validator for this format. A format match does not prove validity or ownership.'}

def validate_azure_storage_format(value):
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        return {'status':'invalid format', 'detail':'Not valid Base64. No provider request was made.'}
    if len(raw) == 64:
        return {'status':'format match', 'detail':'The decoded value is 64 bytes; this does not prove it is an Azure key or that it works.'}
    return {'status':'not confirmed', 'detail':'The decoded value is not 64 bytes. This check alone cannot rule out an Azure credential.'}

def validate_azure_storage(account, key):
    if not re.fullmatch(r'[a-z0-9]{3,24}', account):
        return {'status':'invalid input','detail':'Enter the storage account name (3–24 lowercase letters and digits), not a URL.'}
    try: raw = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error): return {'status':'invalid input','detail':'The account key must be valid Base64.'}
    if len(raw) != 64: return {'status':'invalid input','detail':'This check expects a 64-byte Azure Storage account key.'}
    timestamp = email.utils.formatdate(usegmt=True)
    version = '2021-12-02'
    canonical_headers = 'x-ms-date:' + timestamp + '\nx-ms-version:' + version + '\n'
    canonical_resource = '/' + account + '/\ncomp:properties\nrestype:service'
    signing = '\n'.join(['GET'] + [''] * 11) + '\n' + canonical_headers + canonical_resource
    signature = base64.b64encode(hmac.new(raw, signing.encode(), hashlib.sha256).digest()).decode()
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get('https://' + account + '.blob.core.windows.net/', params={'restype':'service','comp':'properties'}, headers={'x-ms-date':timestamp, 'x-ms-version':version, 'Authorization':'SharedKey ' + account + ':' + signature}, timeout=(5,10), allow_redirects=False)
        if response.status_code == 200:
            return {'status':'authenticated','detail':'Azure Blob Storage accepted the Shared Key for the service-properties request.'}
        return {'status':'inconclusive','detail':'Azure did not confirm this key. Network rules, disabled Shared Key access, account mismatch, clock skew, or invalid credentials can cause failure.'}
    except requests.RequestException:
        return {'status':'inconclusive','detail':'The Azure service could not be reached.'}

def ethereum_balance(address, rpc_url):
    address = address.strip()
    if ethereum_address_status(address) in ('invalid format', 'checksum mismatch'):
        return {'status':'invalid input', 'detail':'Enter a valid Ethereum-style public address. Mixed-case addresses must have a valid checksum.'}
    try:
        rpc_url = safe_url(rpc_url)
        if urllib.parse.urlsplit(rpc_url).scheme != 'https': raise ValueError('HTTPS required')
        with requests.Session() as session:
            session.trust_env = False
            def rpc(method, params):
                response = session.post(rpc_url, json={'jsonrpc':'2.0','id':1,'method':method,'params':params}, timeout=(5,12), allow_redirects=False)
                response.raise_for_status()
                body=response.json()
                if not isinstance(body, dict) or body.get('error') is not None or not isinstance(body.get('result'),str): raise ValueError('Invalid RPC response')
                return body['result']
            if int(rpc('eth_chainId', []),16) != 1:
                return {'status':'wrong network','detail':'The supplied RPC endpoint did not report Ethereum mainnet (chain ID 1).'}
            block = rpc('eth_blockNumber', [])
            block_num = int(block, 16)
            wei = int(rpc('eth_getBalance', [address, block]), 16)
            if block_num < 0 or wei < 0: raise ValueError('Invalid negative value')
        whole, fraction = divmod(wei, 10**18)
        eth = str(whole) + ('.' + str(fraction).zfill(18).rstrip('0') if fraction else '')
        return {'status':'balance retrieved', 'network':'Ethereum mainnet', 'block':block_num,
                'wei':str(wei), 'eth':eth,
                'observed_at':datetime.now(timezone.utc).isoformat(),
                'detail':'Native ETH only; excludes tokens, NFTs, other chains and assets. A zero balance does not prove a private key is safe.'}
    except (ValueError, requests.RequestException, OverflowError):
        return {'status':'inconclusive','detail':'RPC request failed or returned an invalid response. No balance conclusion can be drawn.'}

def validate_github(token):
    if not token or len(token) > 4096 or not re.fullmatch(r'[A-Za-z0-9_.-]+', token):
        return {'status':'invalid input', 'detail':'Provide a single GitHub token without whitespace.'}
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get('https://api.github.com/user', headers={'Authorization':'Bearer '+token, 'Accept':'application/vnd.github+json', 'User-Agent':'ExposureDesk/1.0'}, timeout=(5,10), allow_redirects=False)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict) and isinstance(data.get('login'), str):
                return {'status':'authenticated', 'detail':'GitHub accepted this token for the authenticated-user endpoint.', 'login':data['login']}
        if response.status_code == 401:
            return {'status':'rejected', 'detail':'GitHub rejected this request. The token may be invalid, expired or unsuitable for this endpoint.'}
        return {'status':'inconclusive', 'detail':'GitHub did not confirm this token for the user endpoint. Installation tokens, permissions and rate limits can affect the result.'}
    except (requests.RequestException, ValueError):
        return {'status':'inconclusive', 'detail':'GitHub could not be reached or returned an unreadable response.'}

def validate_aws(access, secret, token):
    if not re.fullmatch(r'(?:AKIA|ASIA)[A-Z0-9]{16}', access) or not re.fullmatch(r'[A-Za-z0-9/+=]{40}', secret):
        return {'status':'invalid input', 'detail':'Supply an AWS access-key ID and a 40-character secret access key.'}
    if access.startswith('ASIA') and not token:
        return {'status':'incomplete', 'detail':'Temporary AWS credentials require their session token.'}
    binary = shutil.which('aws')
    if not binary: return {'status':'unavailable', 'detail':'AWS CLI is not installed.'}
    env={'PATH':os.environ.get('PATH','/usr/bin:/bin'), 'AWS_ACCESS_KEY_ID':access, 'AWS_SECRET_ACCESS_KEY':secret,
         'AWS_EC2_METADATA_DISABLED':'true', 'AWS_CONFIG_FILE':'/dev/null', 'AWS_SHARED_CREDENTIALS_FILE':'/dev/null',
         'AWS_PAGER':'', 'AWS_DEFAULT_REGION':'us-east-1', 'AWS_MAX_ATTEMPTS':'1'}
    if token: env['AWS_SESSION_TOKEN'] = token
    try:
        result = subprocess.run([binary, 'sts', 'get-caller-identity', '--output', 'json', '--no-cli-pager', '--cli-connect-timeout', '5', '--cli-read-timeout', '8'], env=env, capture_output=True, text=True, timeout=18)
        if result.returncode == 0:
            data=json.loads(result.stdout)
            return {'status':'authenticated', 'detail':'AWS STS accepted these credentials.', 'account':data.get('Account'), 'arn':data.get('Arn')}
        if any(x in result.stderr for x in ('InvalidClientTokenId','SignatureDoesNotMatch','ExpiredToken','UnrecognizedClientException')):
            return {'status':'rejected', 'detail':'AWS rejected this credential combination; it may be invalid, expired or incomplete.'}
        return {'status':'inconclusive', 'detail':'AWS did not return a conclusive result. Check network access, region and credential context.'}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {'status':'inconclusive', 'detail':'The AWS request failed or timed out.'}

def record_error(job, exc):
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        category = 'HTTP ' + str(exc.response.status_code)
    elif isinstance(exc, requests.Timeout): category = 'Timeout'
    elif isinstance(exc, requests.ConnectionError): category = 'Connection or DNS failure'
    elif isinstance(exc, ValueError):
        message = str(exc)
        if 'outside the selected origin' in message: category = 'Redirect outside scope'
        elif 'size limit' in message: category = 'Response too large'
        elif 'Too many redirects' in message: category = 'Too many redirects'
        elif 'public internet addresses' in message: category = 'Non-public address blocked'
        elif 'resolved' in message: category = 'DNS resolution failure'
        else: category = 'Invalid URL or blocked request'
    else: category = 'Other fetch or decode error'
    job['errors'] += 1
    counts = job.setdefault('error_categories', {})
    counts[category] = counts.get(category, 0) + 1

def add_finding(job, result, value, page_url, source, image_url=None, line=None):
    kind, severity, explanation = result
    occurrence = {'page': page_url, 'source': source}
    if image_url is not None: occurrence['image'] = image_url
    if line is not None: occurrence['line'] = line
    for finding in job['findings']:
        if finding['value'] == value and finding['type'] == kind:
            locations = finding.setdefault('occurrences', [{'page':finding['page'], 'source':finding['source'], **({'image':finding['image']} if 'image' in finding else {})}])
            if occurrence not in locations: locations.append(occurrence)
            return
    finding = {'type': kind, 'severity': severity, 'explanation': explanation,
               'source': source, 'origin': sanitized(page_url), 'value': value, 'page': page_url,
               'observed_at': datetime.now(timezone.utc).isoformat(), 'occurrences':[occurrence],
               'verification': 'Unverified pattern match; no provider validation was performed.'}
    if image_url is not None: finding['image'] = image_url
    if line is not None: finding['line'] = line
    job['findings'].append(finding)

def decode_image(data):
    try:
        import cv2
        import numpy as np
    except ImportError as exc:
        raise RuntimeError('QR decoder missing: install requirements.txt') from exc
    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None: return []
    detector = cv2.QRCodeDetector()
    ok, values, _, _ = detector.detectAndDecodeMulti(image)
    if ok: return [v for v in values if v]
    value, _, _ = detector.detectAndDecode(image)
    return [value] if value else []


def crawl(job_id, start, limit, max_depth, respect_robots):
    job = JOBS[job_id]
    try:
        start = safe_url(start)
        p = urllib.parse.urlsplit(start)
        origin = (p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80))
        robots = urllib.robotparser.RobotFileParser()
        if respect_robots:
            try:
                _, _, body = fetch(urllib.parse.urljoin(start, '/robots.txt'), origin, 500_000)
                robots.parse(body.decode('utf-8', errors='replace').splitlines())
            except Exception:
                job['warnings'].append('robots.txt unavailable; crawl stopped until access rules can be verified. For an authorized assessment, disable the robots.txt option to proceed.')
                job['status'] = 'failed'
                return
        queue = deque([(start, 0)]); pending = {start}; seen = set(); images = {}
        while queue and (limit is None or len(seen) < limit):
            save_job(job)
            if job.get('cancel_requested'):
                job['status'] = 'stopped'
                break
            job['queued'] = len(queue)
            url, depth = queue.popleft()
            pending.discard(url)
            job['current_url'] = url
            if url in seen: continue
            seen.add(url)
            if respect_robots and not robots.can_fetch(HEADERS['User-Agent'], url):
                coverage = job.setdefault('coverage', {'html':0, 'text':0, 'pdf':0, 'unsupported':0, 'robots_skipped':0, 'pdf_errors':0})
                coverage['robots_skipped'] += 1
                continue
            try:
                page_url, content_type, data = fetch(url, origin)
                job['pages'] += 1
                is_html = 'html' in content_type
                is_text = is_html or any(t in content_type for t in ('text/', 'javascript', 'json', 'xml'))
                is_pdf = 'application/pdf' in content_type or data.startswith(b'%PDF-')
                coverage = job.setdefault('coverage', {'html':0, 'text':0, 'pdf':0, 'unsupported':0, 'robots_skipped':0, 'pdf_errors':0})
                if is_pdf:
                    try:
                        proc = subprocess.run(['pdftotext', '-layout', '-', '-'], input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=True)
                        html = proc.stdout.decode('utf-8', errors='replace')
                    except (FileNotFoundError, subprocess.SubprocessError):
                        coverage['pdf_errors'] += 1
                        job['warnings'].append('A PDF could not be extracted. Ensure pdftotext is installed and the document is readable.')
                        continue
                    coverage['pdf'] += 1
                    source_type = 'PDF text'
                elif is_text:
                    html = data.decode('utf-8', errors='replace')
                    coverage['html' if is_html else 'text'] += 1
                    source_type = 'page text' if is_html else 'text resource'
                else:
                    coverage['unsupported'] += 1
                    continue
                for result, value in text_matches(html): add_finding(job, result, value, page_url, source_type)
                for result, value in azure_resource_matches(html): add_finding(job, result, value, page_url, source_type)
                for result, value in secret_matches(html): add_finding(job, result, value, page_url, source_type)
                if not is_html: continue
                parser = Page(); parser.feed(html)
                for link in parser.links if max_depth is None or depth < max_depth else []:
                    u = urllib.parse.urljoin(page_url, link)
                    try:
                        u = safe_url(u, origin)
                        if u not in seen and u not in pending:
                            queue.append((u, depth + 1))
                            pending.add(u)
                    except ValueError: pass
                for source in parser.images:
                    if job.get('cancel_requested'): break
                    u = urllib.parse.urljoin(page_url, source)
                    try:
                        candidate = urllib.parse.urlsplit(u)
                        if candidate.scheme not in ('http', 'https'):
                            coverage['non_http_images_skipped'] = coverage.get('non_http_images_skipped', 0) + 1
                            continue
                        candidate_origin = (candidate.scheme, (candidate.hostname or '').lower(), candidate.port or (443 if candidate.scheme == 'https' else 80))
                        if candidate_origin != origin:
                            coverage['external_images_skipped'] = coverage.get('external_images_skipped', 0) + 1
                            continue
                        u = safe_url(u, origin)
                        if respect_robots and not robots.can_fetch(HEADERS['User-Agent'], u):
                            coverage['robots_images_skipped'] = coverage.get('robots_images_skipped', 0) + 1
                            continue
                        if u in images:
                            for image_url, payload, result in images[u]: add_finding(job, result, payload, page_url, 'QR image', image_url)
                            continue
                        image_url, typ, img = fetch(u, origin)
                        if not typ.startswith('image/'): continue
                        job['images'] += 1
                        images[u] = []
                        for payload in decode_image(img):
                            result = classify(payload)
                            if result is None:
                                result = next((r for r, value in secret_matches(payload) if value == payload), None)
                            if result is None:
                                result = ('Unclassified QR code', 'review', 'QR content was not recognized; review its context privately. This does not establish whether it is in use.')
                            images[u].append((image_url, payload, result))
                            add_finding(job, result, payload, page_url, 'QR image', image_url)
                    except Exception as exc:
                        if isinstance(exc, RuntimeError): raise
                        record_error(job, exc)
                time.sleep(0.25)
            except RuntimeError: raise
            except Exception as exc: record_error(job, exc)
        job['queued'] = len(queue)
        if job['status'] == 'running' and not job['pages'] and job['errors']:
            job['status'] = 'failed'
            job['warnings'].append('No resources were successfully fetched; review the error categories.')
        if job['status'] == 'running' and queue and limit is not None and len(seen) >= limit:
            job['status'] = 'limited'
            job['warnings'].append('Page limit reached; queued resources remain unchecked.')
    except Exception as exc:
        job['warnings'].append(str(exc))
        job['status'] = 'failed'
    finally:
        job['current_url'] = None
        job['finished_at'] = datetime.now(timezone.utc).isoformat()
        if job['status'] == 'running': job['status'] = 'stopped' if job.get('cancel_requested') else 'complete'
        save_job(job)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass
    def send_json(self, obj, status=200):
        body = json.dumps(obj).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == '/':
            body = (ROOT / 'static/index.html').read_bytes(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        elif self.path == '/api/version':
            self.send_json({'api_version': 9})
        elif self.path == '/api/jobs':
            with LOCK: jobs = [{'id':j['id'], 'status':j['status'], 'scope':j['scope'], 'pages':j['pages'], 'findings':len(j['findings']), 'started_at':j.get('started_at')} for j in JOBS.values()]
            self.send_json(list(reversed(jobs)))
        elif self.path.startswith('/api/jobs/'):
            job = JOBS.get(self.path.split('/')[-1]); self.send_json(job or {'error':'Not found'}, 200 if job else 404)
        else: self.send_json({'error':'Not found'}, 404)
    def do_POST(self):
        try:
            if self.headers.get('Origin') not in (None, 'http://127.0.0.1:8765', 'http://localhost:8765'): raise ValueError('Origin rejected')
            if self.path == '/api/validate':
                length = int(self.headers.get('Content-Length', '0'))
                if length < 1 or length > 12000: raise ValueError('Invalid request size')
                data = json.loads(self.rfile.read(length))
                if data.get('mode') == 'local': result = validate_local(str(data.get('value', '')))
                elif data.get('mode') == 'azure-storage': result = validate_azure_storage_format(str(data.get('value', '')))
                elif data.get('mode') == 'azure-storage-live': result = validate_azure_storage(str(data.get('account', '')).strip(), str(data.get('value', '')).strip())
                elif data.get('mode') == 'ethereum-balance': result = ethereum_balance(str(data.get('address', '')), str(data.get('rpc_url', '')).strip())
                elif data.get('mode') == 'github': result = validate_github(str(data.get('value', '')).strip())
                elif data.get('mode') == 'aws': result = validate_aws(str(data.get('access','')).strip(), str(data.get('secret','')).strip(), str(data.get('token','')).strip())
                else: raise ValueError('Unknown validation mode')
                return self.send_json(result)
            if self.path.startswith('/api/jobs/') and self.path.endswith('/stop'):
                job = JOBS.get(self.path.split('/')[3])
                if not job: return self.send_json({'error':'Not found'},404)
                if job['status'] == 'running':
                    job['cancel_requested'] = True
                    save_job(job)
                return self.send_json(job)
            if self.path != '/api/jobs': return self.send_json({'error':'Not found'},404)
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 4096: raise ValueError('Invalid request size')
            data = json.loads(self.rfile.read(length)); url = safe_url(data['url'])
            limit_value = data.get('limit')
            depth_value = data.get('depth')
            limit = int(limit_value) if limit_value not in (None, '') else None
            depth = int(depth_value) if depth_value not in (None, '') else None
            if limit is not None and limit < 1: raise ValueError('Page limit must be at least 1')
            if depth is not None and depth < 0: raise ValueError('Crawl depth must be 0 or more')
            respect_robots = data.get('respect_robots', True)
            if not isinstance(respect_robots, bool): raise ValueError('Invalid robots.txt option')
            import secrets
            job_id = secrets.token_hex(12)
            job = {'id':job_id,'status':'running','scope':sanitized(url),'pages':0,'images':0,'errors':0,'warnings':[],'findings':[], 'error_categories':{}, 'coverage':{'html':0,'text':0,'pdf':0,'unsupported':0,'robots_skipped':0,'pdf_errors':0}, 'queued':0, 'current_url':None, 'started_at':datetime.now(timezone.utc).isoformat(), 'cancel_requested':False, 'max_depth':depth, 'page_limit':limit, 'respect_robots':respect_robots}
            with LOCK: JOBS[job_id] = job
            save_job(job)
            threading.Thread(target=crawl,args=(job_id,url,limit,depth,respect_robots),daemon=True).start(); self.send_json(job,202)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc: self.send_json({'error':str(exc)},400)

if __name__ == '__main__':
    init_store()
    server = ThreadingHTTPServer(('127.0.0.1',8765), Handler)
    print('QR Exposure Review: http://127.0.0.1:8765', flush=True)
    server.serve_forever()
