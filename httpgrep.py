#!/usr/bin/env python3
# -*- coding: utf-8 -*- ########################################################
#               ____                     _ __                                  #
#    ___  __ __/ / /__ ___ ______ ______(_) /___ __                            #
#   / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                            #
#  /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                             #
#                                           /___/ team                         #
#                                                                              #
# httpgrep                                                                     #
# Async HTTP(S) scanner that greps response bodies and headers for strings     #
# or regex across hosts, ports, CIDR/ranges and TLS-cert vhosts.               #
#                                                                              #
# NOTES                                                                        #
# quick'n'dirty code                                                           #
#                                                                              #
# AUTHOR                                                                       #
# noptrix                                                                      #
#                                                                              #
################################################################################


import re
import sys
import os
import csv
import io
import json
import socket
import ssl
import tempfile
import ipaddress
import random
import termios
import signal
import resource
import asyncio
import warnings
import getopt
import httpx

try:
  import uvloop
except ImportError:
  uvloop = None

try:
  import aiodns
except ImportError:
  aiodns = None


__author__ = 'noptrix'
__version__ = '3.3'
__copyright__ = 'Santa Clause'
__license__ = 'MIT'


SUCCESS = 0
FAILURE = 1

HTTPS_PORTS = (443, 1443, 2443, 3443, 4443, 5443, 6443, 7443, 8443, 9443)

HTTP_METHODS = ('head', 'get', 'post', 'put', 'delete', 'patch', 'options')

SESSION = 'httpgrep.session'

URL_PAD = 38
VHOST_PAD = 28

# only the first 256 KB of a body is read + searched (speed)
MAX_BODY = 256 * 1024

_resolver = None
_dns_cache = {}
_sem = None

NORM = '\033[0m'
BOLD = '\033[1;37;10m'
RED = '\033[1;31;10m'
GREEN = '\033[1;32;10m'
YELLOW = '\033[1;33;10m'
BLUE = '\033[1;34;10m'

BANNER = BLUE + r'''    __    __  __
   / /_  / /_/ /_____  ____ _________  ____
  / __ \/ __/ __/ __ \/ __ `/ ___/ _ \/ __ \
 / / / / /_/ /_/ /_/ / /_/ / /  /  __/ /_/ /
/_/ /_/\__/\__/ .___/\__, /_/   \___/ .___/
             /_/    /____/         /_/
''' + NORM + '''
     --== [ by nullsecurity.net ] ==--'''

HELP = BOLD + '''usage''' + NORM + '''

  httpgrep -h <args> -s <arg> [opts] | <misc>

''' + BOLD + '''target options''' + NORM + '''

  -h <hosts|file>   - single host/url or host-/cidr-range or file containing
                      hosts or file containing URLs, e.g.: foobar.net,
                      192.168.0.1-192.168.0.254, 192.168.0.0/24, /tmp/hosts.txt
                      NOTE: hosts can also contain ':<ports>' on cmdline or in
                      file, where <ports> is a single port, comma-list or
                      range, e.g.: foo.net:8080, foo.net:80,443, 10.0.0.1:1-1024
  -p <ports|file>   - port(s) to connect to: single port, comma-separated list,
                      range, or a file with one spec per line, e.g.: 80,
                      80,443,8080, 8000-8100, /tmp/ports.txt
                      (default: 80, or 443 when -t is given)
  -t                - force TLS/SSL on all ports. by default the scheme is
                      auto-detected per port (plain http, switching to TLS if
                      the port speaks it)
  -u <URI|file>     - URI or comma-separated URIs or file with URIs (one per
                      line) to search given strings in, e.g.: /foobar/,
                      /foo.html, /admin,/login, /tmp/paths.txt (default: /)
  -r                - perform reverse dns lookup for given IPv4 addresses
                      (resolved concurrently before scanning)

''' + BOLD + '''http options''' + NORM + '''

  -X <method>       - specify HTTP request method to use (default: get).
                      use '?' to list available methods.
  -a <user:pass>    - http auth credentials (format: 'user:pass')
  -U <UA>           - set custom User-Agent (default: latest ms edge, windows)
  -A                - use random user-agent per request
  -R <headers>      - set custom headers (format: 'foo=bar;lol=lulz;...')
  -C <cookies>      - set cookies (format: 'foo=bar;lol=lulz;...')
  -F                - don't follow HTTP redirects
  -L <num>          - max redirects to follow (default: 10; ignored with -F)
  -E                - verify TLS/SSL certificates (default: no verification)
  -P <proxy>        - use proxy (format: '[http|https|socks4|socks5]://host:port')
                      (socks needs the 'httpx[socks]' / socksio package)
  -f <codes>        - only report responses with given HTTP status codes,
                      e.g.: '200', '200,301,302'
  -e <codes>        - exclude responses with given HTTP status codes,
                      e.g.: '404', '403,404,500'

''' + BOLD + '''search options''' + NORM + '''

  -s <str|file>     - a single string/regex or multile strings/regex in a file
                      to find in given URIs and HTTP response headers,
                      e.g.: 'tomcat 8', '/tmp/igot0daysforthese.txt'
  -S <str|file>     - invert (grep -v): drop ALL matches of a response if this
                      string/regex (or file) appears anywhere in its body or
                      headers, e.g. to filter out dynamic error / 404 pages
  -w <where>        - search strings in given places (default: headers,body)
  -b <bytes>        - num bytes of context to show from a body match
                      (default: 64). NOTE: only the first 256 KB of a body
                      is read and searched (for speed)
  -i                - use case-insensitive search
  -I                - use case-insensitive invert (for -S)

''' + BOLD + '''scan options''' + NORM + '''

  -x <num>          - max concurrent connections (async; default: 1000). raise
                      ulimit -n accordingly for very high values
  -c <seconds>      - per-host connect + read timeout in seconds, also caps
                      body read time (default: 3.0)
  -G <seconds>      - global timeout: hard-stop the whole scan after N seconds
                      (safety net against any hang; default: none)
  -1                - stop scanning a host after its first match (skips its
                      remaining uris, ports and search strings)
  -z                - scan targets in random order (for cidr-/host-range or
                      target file; loads all targets into memory first)
  -W                - save/resume: on ctrl+c write progress to httpgrep.session;
                      rerun with -W to resume from it (else start fresh)
  -T                - pull (v)hosts from the TLS cert (CN + SAN) and scan them
                      too: against the same target via host header AND the
                      hostname directly. needs TLS (-t or a *443 port).

''' + BOLD + '''output options''' + NORM + '''

  -l <file>         - log found matches to <file>.<fmt> per chosen -O format
                      (e.g. -l out -O csv,jsonl => out.csv, out.jsonl)
  -O <formats>      - log file format(s), comma-list of: txt, csv, jsonl
                      (default: txt; use '?' to list). terminal output always
                      stays human-readable.
  -v                - verbose: print each url as it gets scanned

''' + BOLD + '''misc options''' + NORM + '''

  -H                - print help
  -V                - print version information

''' + BOLD + '''examples''' + NORM + '''

  # grep for 'apache' in headers and body of a single host
  $ httpgrep -h foobar.net -s apache

  # scan a CIDR range on port 8080, search for 'tomcat' in body only
  $ httpgrep -h 192.168.0.0/24 -p 8080 -s tomcat -w body

  # scan a host across multiple ports and a port range for 'jenkins'
  $ httpgrep -h 192.168.0.10 -p 80,443,8080,8000-8100 -s jenkins -i

  # scan host list, search string file, log matches (-> /tmp/out.txt)
  $ httpgrep -h /tmp/hosts.txt -s /tmp/strings.txt -x 200 -l /tmp/out

  # grep for 'admin' case-insensitively across multiple URIs via TLS
  $ httpgrep -h foobar.net -t -u /admin,/login,/dashboard -s admin -i

  # scan IP range, reverse DNS, only report 200 responses
  $ httpgrep -h 10.0.0.1-10.0.0.254 -s 'powered by' -r -f 200

  # search headers only, don't follow redirects, verbose output
  $ httpgrep -h foobar.net -s 'X-Powered-By' -w headers -F -v

  # grep for 'admin', but drop dynamic error pages (invert, case-insensitive)
  $ httpgrep -h 192.168.0.0/24 -s admin -i -S 'error|not found' -I

  # route through proxy, custom UA, search for version strings
  $ httpgrep -h /tmp/hosts.txt -s 'nginx/1\\.' -P http://127.0.0.1:8080 -U 'curl/8.0'

  # scan with http basic auth, 30s timeout, random user-agent
  $ httpgrep -h foobar.net -s secret -a admin:password -c 30 -A

  # only scan hosts with a valid TLS cert, log jsonl (-> found.jsonl)
  $ httpgrep -h /tmp/hosts.txt -t -s login -E -l found -O jsonl

  # big resumable scan: ctrl+c saves state, rerun with -W to continue; also
  # cap the whole run at 1 hour as a hang safety net
  $ httpgrep -h 10.0.0.0/16 -p 80,443 -s admin -W -G 3600
'''


USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/123.0.0.0 Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; FreeBSD amd64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 OPR/107.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:122.0) Gecko/20100101 Firefox/122.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Android 13; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0',
  'Mozilla/5.0 (Linux; Android 13; CPH2451) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 12; moto g power) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.66 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/122.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/121.0.2277.107 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.66 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 14; SM-S921U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0',
]

opts = {
  'hosts': None,
  'ports': None,
  'ssl': False,
  'uri': '/',
  'searchstr': '',
  'where': ('headers', 'body'),
  'method': 'get',
  'auth': False,
  'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
  'rand_agent': False,
  'headers': {},
  'cookies': {},
  'no_redir': False,
  'max_redirs': 10,
  'filter_codes': [],
  'exclude_codes': [],
  'proxy': None,
  'bytes': 64,
  'concurrency': 1000,
  'timeout': 3.0,
  'gtimeout': None,
  'case_in': False,
  'invertstr': '',
  'invert_case': False,
  'skip_on_hit': False,
  'rptr': False,
  'rand_order': False,
  'vhost': False,
  'logfile': False,
  'verbose': False,
  'formats': ['txt'],
  'verify': False,
  'resume': False,
}


def log(msg='', _type='normal', esc='\n'):
  iprefix = f'{BOLD}{BLUE}[+]{NORM}'
  gprefix = f'{BOLD}{GREEN}[*]{NORM}'
  wprefix = f'{BOLD}{YELLOW}[!]{NORM}'
  eprefix = f'{BOLD}{RED}[-]{NORM}'
  vprefix = f'{BOLD}[>]{NORM}'

  if _type == 'normal':
    sys.stdout.write(f'{msg}')
  elif _type == 'verbose':
    sys.stderr.write(f'{vprefix} {msg}{esc}')
  elif _type == 'info':
    sys.stderr.write(f'{iprefix} {msg}{esc}')
  elif _type == 'good':
    sys.stderr.write(f'{gprefix} {msg}{esc}')
  elif _type == 'warn':
    sys.stderr.write(f'{wprefix} {msg}{esc}')
  elif _type == 'error':
    sys.stderr.write(f'{eprefix} {msg}{esc}')
    sys.exit(FAILURE)

  return


def get_user_agent():
  if opts['rand_agent']:
    return random.choice(USER_AGENTS)
  return opts['ua']


def parse_kv(s):
  parsed = {}
  for item in s.split(';'):
    kv = item.strip().split('=', 1)
    if len(kv) == 2:
      parsed[kv[0].strip()] = kv[1].strip()
  return parsed


def parse_ports(spec):
  ports = []
  for part in str(spec).split(','):
    part = part.strip()
    if not part:
      continue
    if '-' in part:
      lo, hi = (int(x) for x in part.split('-', 1))
      if lo > hi:
        lo, hi = hi, lo
      ports.extend(range(lo, hi + 1))
    else:
      ports.append(int(part))

  seen = set()
  result = []
  for p in ports:
    if not 0 < p < 65536:
      raise ValueError(f'invalid port: {p}')
    if p not in seen:
      seen.add(p)
      result.append(p)

  if not result:
    raise ValueError(f'invalid port spec: {spec}')

  return result


def ports_from_arg(spec):
  if os.path.isfile(spec):
    with open(spec, 'r', encoding='utf-8') as f:
      spec = ','.join(line.strip() for line in f if line.strip())
  return parse_ports(spec)


def split_port(entry):
  host_part, sep, portspec = entry.rpartition(':')
  if not sep:
    return entry, None
  return host_part, parse_ports(portspec)


async def resolve_rptr(host):
  if host in _dns_cache:
    return _dns_cache[host]
  name = host
  try:
    if _resolver:
      name = (await _resolver.gethostbyaddr(host)).name or host
    else:
      loop = asyncio.get_running_loop()
      name, _ = await loop.getnameinfo((host, 0),
                                       socket.NI_NAMEREQD | socket.NI_NUMERICSERV)
  except Exception:
    name = host
  _dns_cache[host] = name
  return name


def is_ipv4(host):
  try:
    ipaddress.IPv4Address(host)
    return True
  except ValueError:
    return False


async def port_open(host, port):
  # tcp preflight: skip the http request on dead ports
  try:
    async with _sem:
      _, writer = await asyncio.wait_for(asyncio.open_connection(host, port),
                                         timeout=opts['timeout'])
      writer.close()
      try:
        await writer.wait_closed()
      except Exception:
        pass
    return True
  except Exception:
    return False


async def cert_names(host, port):
  names = set()
  try:
    ctx = ssl._create_unverified_context()
    sni = None if is_ipv4(host) else host
    async with _sem:
      _, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
        timeout=opts['timeout'])
      der = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
      writer.close()
      try:
        await writer.wait_closed()
      except Exception:
        pass
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile('w', suffix='.pem') as tf:
      tf.write(pem)
      tf.flush()
      cert = ssl._ssl._test_decode_cert(tf.name)
  except Exception:
    return names

  for rdn in cert.get('subject', ()):
    for k, v in rdn:
      if k == 'commonName':
        names.add(v)
  for typ, val in cert.get('subjectAltName', ()):
    if typ == 'DNS':
      names.add(val)

  # drop wildcards (not usable as a literal host), empties, control chars
  return {n for n in names if n and '*' not in n and n.isprintable()}


def get_uris():
  uri = opts['uri']
  if os.path.isfile(uri):
    with open(uri, 'r', encoding='utf-8') as f:
      raw = [line.rstrip() for line in f]
  elif ',' in uri:
    raw = uri.split(',')
  else:
    raw = [uri]

  for u in raw:
    u = u.strip()
    if not u:
      continue
    if not u.startswith('/'):
      u = '/' + u
    yield u

  return


def get_strings(strings):
  if os.path.isfile(strings):
    with open(strings, 'r', encoding='utf-8') as f:
      for string in f:
        string = string.rstrip()
        if string:
          yield string
  else:
    yield strings # single string

  return


def compile_patterns(strings):
  # str pattern for headers, bytes pattern for body (skips charset decoding)
  patterns = []
  for s in strings:
    if not s:                           # empty pattern would match everything
      continue
    try:
      sp = re.compile(s, opts['case_in'])
      bp = re.compile(s.encode('utf-8'), opts['case_in'])
    except re.error as err:
      log(f'skipping invalid regex {s!r}: {err}', 'warn')
      continue
    patterns.append((sp, bp))

  if not patterns:
    log('no valid search strings given', 'error')

  # fast gate: one combined search; the per-pattern loop only runs on a hit
  raw = [sp.pattern for sp, bp in patterns]
  comb_s = re.compile('|'.join(f'(?:{r})' for r in raw), opts['case_in'])
  comb_b = re.compile(b'|'.join(b'(?:' + r.encode('utf-8') + b')' for r in raw),
                      opts['case_in'])

  return patterns, comb_s, comb_b


def compile_invert(spec, case):
  if not spec:
    return None, None
  raw = []
  for s in get_strings(spec):
    if not s:
      continue
    try:
      re.compile(s, case)
    except re.error as err:
      log(f'skipping invalid invert regex {s!r}: {err}', 'warn')
      continue
    raw.append(s)
  if not raw:
    return None, None
  inv_s = re.compile('|'.join(f'(?:{r})' for r in raw), case)
  inv_b = re.compile(b'|'.join(b'(?:' + r.encode('utf-8') + b')' for r in raw),
                     case)
  return inv_s, inv_b


def req_headers(vhost=None):
  h = {'User-Agent': get_user_agent()}
  h.update(opts['headers'])
  if vhost:
    h['Host'] = vhost
  # httpx rejects non-ascii header values; send them as latin-1 bytes
  return {k: (v.encode('latin-1', 'replace') if isinstance(v, str)
              and not v.isascii() else v) for k, v in h.items()}


def write_log(path, line):
  try:
    with open(path, 'a+', encoding='utf-8') as f:
      print(line, file=f)
  except Exception:
    log(f'could not write to logfile {path}', 'warn')


def emit(url, vhost, kind, content):
  pretty = format_row(url, vhost, kind, content)

  log(pretty, 'good')
  if not opts['logfile']:
    return
  for fmt in opts['formats']:
    if fmt == 'csv':
      line = csv_line([url, vhost, kind, content])
    elif fmt == 'jsonl':
      line = json.dumps({'url': url, 'vhost': vhost, 'type': kind,
                         'match': content})
    else:
      line = pretty
    write_log(f"{opts['logfile']}.{fmt}", line)


async def probe(client, url, vhost, patterns, found):
  pats, comb_s, comb_b, inv_s, inv_b = patterns

  if found and found['hit']:        # -1: host already matched, skip the rest
    return

  if opts['verbose']:
    log(f'scanning {url}', 'verbose')

  await _sem.acquire()
  try:
    async with client.stream(opts['method'], url, headers=req_headers(vhost),
                             follow_redirects=not opts['no_redir']) as r:
      if opts['filter_codes'] and r.status_code not in opts['filter_codes']:
        return
      if opts['exclude_codes'] and r.status_code in opts['exclude_codes']:
        return

      # read body if we search it, or if an invert pattern must be checked.
      # capped in size + total time (asyncio.timeout beats slow-drip)
      body = bytearray()
      if 'body' in opts['where'] or inv_b is not None:
        try:
          async with asyncio.timeout(opts['timeout']):
            async for chunk in r.aiter_bytes(8192):
              body += chunk
              if len(body) >= MAX_BODY:
                break
        except Exception:
          pass

      # invert (-S) is response-wide: drop ALL matches if it hits body OR headers
      if inv_b is not None:
        hdrs = '\n'.join(f'{kb.decode("latin-1")}: {vb.decode("latin-1")}'
                         for kb, vb in r.headers.raw)
        if inv_b.search(body) or inv_s.search(hdrs):
          return

      if 'body' in opts['where'] and body and comb_b.search(body):
        for sp, bp in pats:
          m = bp.search(body)
          if m:
            snip = body[m.start():m.start()+opts['bytes']].decode('utf-8',
                                                                  'replace')
            emit(url, vhost or '', 'body', repr(snip))
            if found is not None:
              found['hit'] = True
              return

      if 'headers' in opts['where']:
        for kb, vb in r.headers.raw:                  # raw -> original case
          k = kb.decode('latin-1')
          v = vb.decode('latin-1')
          if comb_s.search(k) or comb_s.search(v):
            for sp, bp in pats:
              if sp.search(k) or sp.search(v):
                emit(url, vhost or '', 'header', safe_text(f'{k}: {v}'))
                if found is not None:
                  found['hit'] = True
                  return
  except Exception:
    return
  finally:
    _sem.release()


async def scan(client, host, ports, patterns, uris):
  if opts['rptr'] and ports is not None and is_ipv4(host):
    host = await resolve_rptr(host)

  found = {'hit': False} if opts['skip_on_hit'] else None   # -1: shared per host

  if ports is None:                 # full url given as-is
    await probe(client, host, None, patterns, found)
    return

  if found is None:
    # ports of one host run concurrently; the global _sem caps connections
    await asyncio.gather(*(scan_port(client, host, port, patterns, uris, found)
                           for port in ports), return_exceptions=True)
  else:
    for port in ports:              # -1: sequential so a hit skips the rest
      if found['hit']:
        break
      await scan_port(client, host, port, patterns, uris, found)


async def scheme_ok(client, host, port, scheme):
  # connection probe: True if http(s) speaks here, False on protocol/tls mismatch
  try:
    async with _sem:
      await client.head(f'{scheme}://{host}:{port}/', follow_redirects=False)
    return True
  except Exception:
    return False


async def detect_scheme(client, host, port):
  # default: speak plain, auto-switch to TLS if the port wants it (-t forces it)
  if opts['ssl']:
    return 'https'
  guess = 'https' if port in HTTPS_PORTS else 'http'
  for scheme in (guess, 'http' if guess == 'https' else 'https'):
    if await scheme_ok(client, host, port, scheme):
      return scheme
  return None


async def scan_port(client, host, port, patterns, uris, found):
  if not await port_open(host, port):
    return

  scheme = await detect_scheme(client, host, port)
  if scheme is None:                # open but speaks neither http nor https
    return

  vhosts = []
  if opts['vhost'] and scheme == 'https':
    vhosts = [vh for vh in await cert_names(host, port) if vh != host]

  if found is None:
    await asyncio.gather(*(probe(client, build_url(scheme, host, port, u), None,
                                 patterns, found) for u in uris),
                         return_exceptions=True)
    for vh in vhosts:
      await asyncio.gather(
        *(probe(client, build_url(scheme, host, port, u), vh, patterns, found)
          for u in uris),
        *(probe(client, build_url(scheme, vh, port, u), None, patterns, found)
          for u in uris),
        return_exceptions=True)
  else:
    for u in uris:                  # -1: sequential, bail on first hit
      if found['hit']:
        return
      await probe(client, build_url(scheme, host, port, u), None, patterns,
                  found)
    for vh in vhosts:
      for u in uris:
        if found['hit']:
          return
        await probe(client, build_url(scheme, host, port, u), vh, patterns,
                    found)
        if found['hit']:
          return
        await probe(client, build_url(scheme, vh, port, u), None, patterns,
                    found)


def build_url(scheme, host, port, uri):
  return f'{scheme}://{host}:{port}{uri}'


def format_row(url, vhost, kind, content):
  cols = f'{url:<{URL_PAD}}'
  if opts['vhost']:
    cols = f'{cols} | {vhost:<{VHOST_PAD}}'
  return f'{cols} | {kind:<6} | {content}'


def safe_text(s):
  # escape control chars so a malicious response can't mess with the terminal
  return ''.join(c if c.isprintable() or c == ' ' else f'\\x{ord(c):02x}'
                 for c in s)


def csv_line(fields):
  safe = []
  for f in fields:
    f = str(f)
    if f[:1] in ('=', '+', '-', '@', '\t'):     # neutralize csv formula injection
      f = "'" + f
    safe.append(f)
  buf = io.StringIO()
  csv.writer(buf).writerow(safe)
  return buf.getvalue().rstrip('\r\n')


def list_formats():
  log('available output formats\n', 'info')
  for name, desc in (
      ('txt', 'pretty aligned columns (default)'),
      ('csv', 'url,vhost,type,match rows (with header)'),
      ('jsonl', 'one json object per match')):
    log(f'{name:6} - {desc}', 'verbose')

  return


def list_methods():
  log('supported http methods\n', 'info')
  for method in HTTP_METHODS:
    log(method, 'verbose')

  return


def parse_target(entry, expand):
  # full url: scheme/port already baked in, use as-is (ports n/a)
  if '://' in entry:
    yield (entry, None)
    return

  host_part, ports = split_port(entry)
  if ports is None:
    ports = opts['ports']

  if expand and '/' in host_part:
    for ipaddr in ipaddress.IPv4Network(host_part, strict=False).hosts():
      yield (str(ipaddr), ports)
  elif expand and '-' in host_part:
    try:
      start = ipaddress.IPv4Address(host_part.split('-')[0])
      end = ipaddress.IPv4Address(host_part.split('-')[1])
      for i in range(int(start), int(end) + 1):
        yield (str(ipaddress.IPv4Address(i)), ports)
    except ValueError:
      yield (host_part, ports)
  else:
    yield (host_part, ports)

  return


def get_hosts(hosts):
  try:
    if os.path.isfile(hosts):
      with open(hosts, 'r', encoding='utf-8') as f:
        for line in f:
          line = line.rstrip()
          if line:
            yield from parse_target(line, expand=False)
    else:
      yield from parse_target(hosts, expand=True)
  except Exception as err:
    log(str(err).lower() or 'invalid host spec', 'error')

  return


def check_search_place():
  for place in opts['where']:
    if place not in ('headers', 'body'):
      log("nope, i only know 'body' and 'headers'", 'error')

  return


def check_http_method():
  if opts['method'] not in HTTP_METHODS:
    log(f'unsupported http method: {opts["method"]}', 'error')

  return


def check_auth():
  if opts['auth']:
    if len(opts['auth']) != 2:
      log('wrong user:pass supplied', 'error')

  return


def check_argv():
  # validate parsed values, not raw argv (which '-s -h' could fool)
  if not opts['hosts'] or not opts['searchstr']:
    log('WTF? mount /dev/brain!', 'error')

  return


def parse_cmdline(cmdline):
  try:
    _opts, _args = getopt.getopt(cmdline, 'h:p:tTu:s:S:w:X:a:U:AR:C:FL:P:b:x:c:G:iIrz1Wl:f:e:vEO:VH')
    for o, a in _opts:
      if o == '-h':
        opts['hosts'] = a
      elif o == '-p':
        opts['ports'] = ports_from_arg(a)
      elif o == '-t':
        opts['ssl'] = True
      elif o == '-T':
        opts['vhost'] = True
      elif o == '-u':
        opts['uri'] = a
      elif o == '-s':
        opts['searchstr'] = a
      elif o == '-S':
        opts['invertstr'] = a
      elif o == '-w':
        opts['where'] = [w.strip() for w in a.split(',')]
      elif o == '-X':
        if a == '?':
          list_methods()
          sys.exit(SUCCESS)
        opts['method'] = a
      elif o == '-a':
        opts['auth'] = tuple(a.split(':', 1))
      elif o == '-U':
        opts['ua'] = a
      elif o == '-A':
        opts['rand_agent'] = True
      elif o == '-R':
        opts['headers'].update(parse_kv(a))
      elif o == '-C':
        opts['cookies'].update(parse_kv(a))
      elif o == '-F':
        opts['no_redir'] = True
      elif o == '-L':
        opts['max_redirs'] = int(a)
      elif o == '-P':
        opts['proxy'] = a
      elif o == '-b':
        opts['bytes'] = int(a)
      elif o == '-x':
        opts['concurrency'] = int(a)
      elif o == '-c':
        opts['timeout'] = float(a)
      elif o == '-G':
        opts['gtimeout'] = float(a)
      elif o == '-f':
        opts['filter_codes'] = [int(c) for c in a.split(',')]
      elif o == '-e':
        opts['exclude_codes'] = [int(c) for c in a.split(',')]
      elif o == '-i':
        opts['case_in'] = re.IGNORECASE
      elif o == '-I':
        opts['invert_case'] = re.IGNORECASE
      elif o == '-1':
        opts['skip_on_hit'] = True
      elif o == '-r':
        opts['rptr'] = True
      elif o == '-z':
        opts['rand_order'] = True
      elif o == '-W':
        opts['resume'] = True
      elif o == '-l':
        opts['logfile'] = a
      elif o == '-v':
        opts['verbose'] = True
      elif o == '-E':
        opts['verify'] = True
      elif o == '-O':
        if a == '?':
          list_formats()
          sys.exit(SUCCESS)
        fmts = [x.strip() for x in a.split(',') if x.strip()]
        for fmt in fmts:
          if fmt not in ('txt', 'csv', 'jsonl'):
            log("option -O expects: txt, csv, jsonl (or '?')", 'error')
        opts['formats'] = fmts or ['txt']
      elif o == '-V':
        log(f'httpgrep v{__version__}', _type='info')
        sys.exit(SUCCESS)
      elif o == '-H':
        log(HELP)
        sys.exit(SUCCESS)
  except (getopt.GetoptError, ValueError) as err:
    log(err.args[0].lower(), 'error')

  return


def check_argc(cmdline):
  if len(cmdline) == 0:
    log('use -H for help', 'error')

  return


def check_fd_limit(concurrency):
  # async opens many sockets at once; make sure the open-file limit covers it
  try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = concurrency * 2 + 64                  # ~preflight + http fd per worker
    if soft < need:
      try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(need, hard), hard))
        soft = min(need, hard)
      except Exception:
        pass
      if soft < need:
        log(f'open-file limit ({soft}) is below what -x {concurrency} needs '
            f'(~{need}); raise it (ulimit -n) or lower -x', 'warn')
  except Exception:
    pass


async def run_scan(targets, patterns, uris, done, session_argv):
  n = opts['concurrency']

  global _resolver, _sem
  _sem = asyncio.Semaphore(n)
  if aiodns:
    try:
      _resolver = aiodns.DNSResolver(timeout=opts['timeout'])
    except Exception:
      _resolver = None

  def abort(reason):
    if opts['resume']:
      log(f'{reason}; saving session', 'warn')
      try:
        with open(SESSION, 'w', encoding='utf-8') as f:
          json.dump({'argv': session_argv, 'done': sorted(done)}, f)
        log(f'saved {len(done)} done targets to {SESSION} '
            '(rerun with -W to resume)', 'warn')
      except Exception as err:
        log(f'could not save session: {err}', 'warn')
    else:
      log(reason, 'warn')
    sys.stderr.flush()                 # os._exit won't flush buffered output
    os._exit(SUCCESS)

  loop = asyncio.get_running_loop()
  loop.add_signal_handler(signal.SIGINT, abort, 'you aborted me')
  if opts['gtimeout']:
    loop.call_later(opts['gtimeout'], abort,
                    f'global timeout ({opts["gtimeout"]}s) reached, stopping')

  # no keep-alive: partial reads (body-cap/header-skip) make pooling slower here
  try:
    client = httpx.AsyncClient(
      verify=opts['verify'], timeout=httpx.Timeout(opts['timeout']),
      limits=httpx.Limits(max_connections=n, max_keepalive_connections=0),
      auth=opts['auth'] or None, cookies=opts['cookies'] or None,
      max_redirects=opts['max_redirs'], proxy=opts['proxy'] or None)
  except Exception as err:
    log(f'bad proxy / client config: {err}', 'error')

  queue = asyncio.Queue(maxsize=n * 2)             # bounded -> back-pressure

  async def worker():
    while True:
      item = await queue.get()
      if item is None:
        queue.task_done()
        return
      host, ports = item
      try:
        await scan(client, host, ports, patterns, uris)
        if opts['resume']:
          done.add(f'{host}|{ports}')
      except Exception:
        pass
      finally:
        queue.task_done()

  workers = [asyncio.create_task(worker()) for _ in range(n)]
  for host, ports in targets:
    if opts['resume'] and f'{host}|{ports}' in done:
      continue
    await queue.put((host, ports))
  for _ in range(n):
    await queue.put(None)
  await asyncio.gather(*workers)
  await client.aclose()


def main(cmdline):
  sys.stderr.write(f'{BANNER}\n\n')
  check_argc(cmdline)
  parse_cmdline(cmdline)

  # -W resume: restore the saved run's argv + done-set if a session exists
  session_argv = list(cmdline)
  done = set()
  resume_note = None       # emitted after 'game started' so order stays sane
  if opts['resume'] and os.path.isfile(SESSION):
    try:
      with open(SESSION, encoding='utf-8') as f:
        saved = json.load(f)
      session_argv = saved['argv']
      parse_cmdline(session_argv)
      opts['resume'] = True
      done = set(saved['done'])
      resume_note = ('info', f'resuming {SESSION}: {len(done)} targets '
                     'already done')
    except Exception as err:
      resume_note = ('warn', f'could not read {SESSION} ({err}); starting fresh')

  check_argv()
  check_http_method()
  check_search_place()
  check_auth()

  if opts['ports'] is None:
    opts['ports'] = [443] if opts['ssl'] else [80]

  if opts['concurrency'] < 1:
    log('concurrency (-x) must be >= 1', 'error')

  if opts['max_redirs'] < 0:
    log('max redirects (-L) must be >= 0', 'error')

  check_fd_limit(opts['concurrency'])

  log('w00t w00t, game started', 'info')
  if resume_note:
    log(resume_note[1], resume_note[0])

  uris = list(get_uris())
  patterns = compile_patterns(get_strings(opts['searchstr']))
  patterns = (*patterns, *compile_invert(opts['invertstr'], opts['invert_case']))

  log(f'wait bitch, scanning: {opts["hosts"]}', 'info')
  if opts['logfile'] and 'csv' in opts['formats']:
    # write the header only for a fresh/empty file (logfiles are append mode)
    csvp = f"{opts['logfile']}.csv"
    if not os.path.isfile(csvp) or os.path.getsize(csvp) == 0:
      write_log(csvp, csv_line(['url', 'vhost', 'type', 'match']))

  targets = get_hosts(opts['hosts'])
  if opts['rand_order']:
    targets = list(targets)
    random.shuffle(targets)

  asyncio.run(run_scan(targets, patterns, uris, done, session_argv),
              loop_factory=uvloop.new_event_loop if uvloop else None)

  if opts['resume'] and os.path.isfile(SESSION):
    os.remove(SESSION)            # finished cleanly, nothing left to resume

  log('n00b n00b, game over', 'info')

  return


if __name__ == '__main__':
  warnings.filterwarnings('ignore')
  try:
    _fd = sys.stdin.fileno()
    _tc = termios.tcgetattr(_fd)
    _tc[3] &= ~termios.ECHOCTL
    termios.tcsetattr(_fd, termios.TCSADRAIN, _tc)
  except Exception:
    pass
  try:
    main(sys.argv[1:])
  except KeyboardInterrupt:
    log('\n')
    log('you aborted me', 'warn')
    os._exit(SUCCESS)

