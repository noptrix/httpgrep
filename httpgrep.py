#!/usr/bin/env python3
# -*- coding: utf-8 -*- ########################################################
#               ____                     _ __                                  #
#    ___  __ __/ / /__ ___ ______ ______(_) /___ __                            #
#   / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                            #
#  /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                             #
#                                           /___/ team                         #
#                                                                              #
# httpgrep                                                                     #
# Scans HTTP servers to find given strings in HTTP body and HTTP response      #
# headers.                                                                     #
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
import socket
import ipaddress
import random
import time
import termios
import requests
import warnings
import getopt
from concurrent.futures import ThreadPoolExecutor


__author__ = 'noptrix'
__version__ = '2.7'
__copyright__ = 'santa clause'
__license__ = 'MIT'


SUCCESS = 0
FAILURE = 1

NORM = '\033[0m'
BOLD = '\033[1;37;10m'
RED = '\033[1;31;10m'
GREEN = '\033[1;32;10m'
YELLOW = '\033[1;33;10m'
BLUE = '\033[1;34;10m'
MAGENTA = '\033[1;35;10m'

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
                      NOTE: hosts can also contain ':<port>' on cmdline or in
                      file.
  -p <port>         - port to connect to (default: 80 if hosts were given)
  -t                - use TLS/SSL to connect to service
  -u <URI|file>     - URI or comma-separated URIs or file with URIs (one per
                      line) to search given strings in, e.g.: /foobar/,
                      /foo.html, /admin,/login, /tmp/paths.txt (default: /)
  -r                - perform reverse dns lookup for given IPv4 addresses
                      NOTE: this will slow down the scanz

''' + BOLD + '''http options''' + NORM + '''

  -X <method>       - specify HTTP request method to use (default: get).
                      use '?' to list available methods.
  -a <user:pass>    - http auth credentials (format: 'user:pass')
  -U <UA>           - set custom User-Agent (default: firefox, rv84, windows)
  -A                - use random user-agent per request
  -R <headers>      - set custom headers (format: 'foo=bar;lol=lulz;...')
  -C <cookies>      - set cookies (format: 'foo=bar;lol=lulz;...')
  -F                - don't follow HTTP redirects
  -P <proxy>        - use proxy (format: '[http|https|socks4|socks5]://host:port')

''' + BOLD + '''search options''' + NORM + '''

  -s <str|file>     - a single string/regex or multile strings/regex in a file
                      to find in given URIs and HTTP response headers,
                      e.g.: 'tomcat 8', '/tmp/igot0daysforthese.txt'
  -S <where>        - search strings in given places (default: headers,body)
  -b <bytes>        - num bytes to read from response. offset == response[0].
                      (default: 64)
  -i                - use case-insensitive search

''' + BOLD + '''scan options''' + NORM + '''

  -x <threads>      - num threads for concurrent scans and checks (default: 80)
  -c <seconds>      - num seconds for socket timeout (default: 3.0)
  -f <codes>        - only report responses with given HTTP status codes,
                      e.g.: '200', '200,301,302'

''' + BOLD + '''output options''' + NORM + '''

  -l <file>         - log found matches to file
  -v                - verbose mode (default: quiet)

''' + BOLD + '''misc options''' + NORM + '''

  -H                - print help
  -V                - print version information

''' + BOLD + '''examples''' + NORM + '''

  # grep for 'apache' in headers and body of a single host
  $ httpgrep -h foobar.net -s apache

  # scan a CIDR range on port 8080, search for 'tomcat' in body only
  $ httpgrep -h 192.168.0.0/24 -p 8080 -s tomcat -S body

  # scan host list, search string file, log matches, 200 threads
  $ httpgrep -h /tmp/hosts.txt -s /tmp/strings.txt -x 200 -l /tmp/out.txt

  # grep for 'admin' case-insensitively across multiple URIs via TLS
  $ httpgrep -h foobar.net -t -u /admin,/login,/dashboard -s admin -i

  # scan IP range, reverse DNS, only report 200 responses
  $ httpgrep -h 10.0.0.1-10.0.0.254 -s 'powered by' -r -f 200

  # search headers only, don't follow redirects, verbose output
  $ httpgrep -h foobar.net -s 'X-Powered-By' -S headers -F -v

  # route through burp, custom UA, search for version strings
  $ httpgrep -h /tmp/hosts.txt -s 'nginx/1\\.' -P http://127.0.0.1:8080 -U 'curl/8.0'

  # scan with http basic auth, 30s timeout, random user-agent
  $ httpgrep -h foobar.net -s secret -a admin:password -c 30 -A
'''


USER_AGENTS = [
  # windows - chrome
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
  ' (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36'
  ' (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  # windows - firefox
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0)'
  ' Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0)'
  ' Gecko/20100101 Firefox/124.0',
  # windows - edge
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
  ' (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
  # macos - chrome
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
  ' (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  # macos - firefox
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0)'
  ' Gecko/20100101 Firefox/125.0',
  # macos - safari
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15'
  ' (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
  # linux - chrome
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
  ' (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  # linux - firefox
  'Mozilla/5.0 (X11; Linux x86_64; rv:125.0)'
  ' Gecko/20100101 Firefox/125.0',
  # linux - chromium
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
  ' (KHTML, like Gecko) Chromium/123.0.0.0 Chrome/123.0.0.0 Safari/537.36',
  # freebsd - firefox
  'Mozilla/5.0 (X11; FreeBSD amd64; rv:125.0)'
  ' Gecko/20100101 Firefox/125.0',
  # freebsd - chrome
  'Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/537.36'
  ' (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
]

opts = {
  'hosts': None,
  'port': 80,
  'ssl': False,
  'uri': '/',
  'searchstr': '',
  'where': ('headers', 'body'),
  'method': 'get',
  'auth': False,
  'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0',
  'rand_agent': False,
  'headers': {},
  'cookies': {},
  'no_redir': False,
  'filter_codes': [],
  'proxy': None,
  'bytes': 64,
  'threads': 80,
  'timeout': 3.0,
  'case_in': False,
  'rptr': False,
  'logfile': False,
  'verbose': False,
}


def log(msg='', _type='normal', esc='\n'):
  iprefix = f'{BOLD}{BLUE}[+]{NORM}'
  gprefix = f'{BOLD}{GREEN}[*]{NORM}'
  wprefix = f'{BOLD}{YELLOW}[!]{NORM}'
  eprefix = f'{BOLD}{RED}[-]{NORM}'
  vprefix = f'{BOLD}    >{NORM}'

  if _type == 'normal':
    sys.stdout.write(f'{msg}')
  elif _type == 'verbose':
    sys.stdout.write(f'{vprefix} {msg}{esc}')
  elif _type == 'info':
    sys.stderr.write(f'{iprefix} {msg}{esc}')
  elif _type == 'good':
    sys.stderr.write(f'{gprefix} {msg}{esc}')
  elif _type == 'warn':
    sys.stderr.write(f'{wprefix} {msg}{esc}')
  elif _type == 'error':
    sys.stderr.write(f'{eprefix} {msg}{esc}')
    sys.exit(FAILURE)
  elif _type == 'spin':
    sys.stderr.flush()
    for i in ('-', '\\', '|', '/'):
      sys.stderr.write(f'\r{BOLD}{BLUE}[{i}] {NORM}{msg} ')
      time.sleep(0.025)
  elif _type == 'file':
    try:
      with open(opts['logfile'], 'a+', encoding='utf-8') as f:
        print(msg, file=f)
    except:
      log('could not open or write to logfile', 'warn')

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


def rptr(ipaddr):
  if opts['rptr']:
    try:
      return socket.gethostbyaddr(ipaddr)[0]
    except:
      return ipaddr

  return ipaddr


def get_uris():
  uri = opts['uri']
  if os.path.isfile(uri):
    with open(uri, 'r', encoding='utf-8') as f:
      for line in f:
        line = line.rstrip()
        if line:
          yield line
  elif ',' in uri:
    for u in uri.split(','):
      u = u.strip()
      if u:
        yield u
  else:
    yield uri

  return


def get_strings(strings):
  if os.path.isfile(strings):
    with open(strings, 'r', encoding='utf-8') as f:
      for string in f:
        yield string.rstrip()
  else:
    yield strings # single string

  return


def http_req(url):
  m = getattr(requests, opts['method'])
  headers = {'User-Agent': get_user_agent()}
  headers.update(opts['headers'])
  proxies = {'http': opts['proxy'], 'https': opts['proxy']} if opts['proxy'] \
    else None
  r = m(url, timeout=opts['timeout'], headers=headers, verify=False,
    auth=opts['auth'], cookies=opts['cookies'], proxies=proxies,
    allow_redirects=not opts['no_redir'])

  return r


def scan(url, string, url_width):
  if opts['verbose']:
    log(f'scanning {url}' + ' ' * 20, 'verbose', esc='\r')
    sys.stdout.flush()

  try:
    r = http_req(url)
  except Exception:
    return

  if opts['filter_codes'] and r.status_code not in opts['filter_codes']:
    return

  u = f'{url:<{url_width}}'

  if 'body' in opts['where']:
    m = re.search(string, r.text, opts['case_in'])
    if m:
      idx = m.start()
      res = repr(r.text[idx:idx+opts['bytes']])
      log(f'{u} | body   | {res}', 'good')
      if opts['logfile']:
        log(f'{u} | body   | {res}', 'file')

  if 'headers' in opts['where']:
    for k, v in r.headers.items():
      if re.search(string, k, opts['case_in']) or \
        re.search(string, v, opts['case_in']):
        log(f'{u} | header | {k}: {v}', 'good')
        if opts['logfile']:
          log(f'{u} | header | {k}: {v}', 'file')

  if opts['verbose']:
    log('\n')

  return


def build_url(host, uri):
  scheme = 'https' if opts['ssl'] else 'http'

  if ':' in host:
    return f'{scheme}://{host}{uri}'

  return f'{scheme}://{host}:{opts["port"]}{uri}'


def get_hosts(hosts):
  try:
    if os.path.isfile(hosts):
      with open(hosts, 'r', encoding='utf-8') as f:
        for host in f:
          yield host.rstrip()
    elif '/' in hosts and 'http' not in hosts:
      for ipaddr in ipaddress.IPv4Network(hosts).hosts():
        yield rptr(str(ipaddr))
    elif '-' in hosts and 'http' not in hosts:
      try:
        start = ipaddress.IPv4Address(hosts.split('-')[0])
        end = ipaddress.IPv4Address(hosts.split('-')[1])
        for i in range(int(start), int(end) + 1):
          yield rptr(str(ipaddress.IPv4Address(i)))
      except ValueError:
        yield hosts
    else:
      yield hosts
  except Exception as err:
    log(err.args[0].lower(), 'error')

  return


def check_search_place():
  if 'headers' not in opts['where'] and 'body' not in opts['where']:
    log("nope, i only know 'body' and 'headers'", 'error')

  return


def check_http_method():
  allowed = ('head', 'get', 'post', 'put', 'delete', 'patch', 'options')

  if opts['method'] == '?':
    log('supported http methods\n', 'info')
    for i in allowed:
      log(f'{i}', 'verbose')
    sys.exit(SUCCESS)
  if opts['method'] not in allowed:
    log(f'unsupported http method: {opts["method"]}', 'error')

  return


def check_auth():
  if opts['auth']:
    if len(opts['auth']) != 2:
      log(f'wrong user:pass supplied', 'error')

  return


def check_argv(cmdline):
  needed = ['-h', '-s', '-V', '-H']

  if '-h' not in cmdline or '-s' not in cmdline or \
    set(needed).isdisjoint(set(cmdline)):
      log('WTF? mount /dev/brain!', 'error')

  return


def parse_cmdline(cmdline):
  global opts

  try:
    _opts, _args = getopt.getopt(sys.argv[1:], 'h:p:tu:s:S:X:a:U:AR:C:FP:b:x:c:irl:f:vVH')
    for o, a in _opts:
      if o == '-h':
        opts['hosts'] = a
      elif o == '-p':
        opts['port'] = a
      elif o == '-t':
        opts['ssl'] = True
      elif o == '-u':
        opts['uri'] = a
      elif o == '-s':
        opts['searchstr'] = a
      elif o == '-S':
        opts['where'] = a.split(',')
      elif o == '-X':
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
      elif o == '-P':
        opts['proxy'] = a
      elif o == '-b':
        opts['bytes'] = int(a)
      elif o == '-x':
        opts['threads'] = int(a)
      elif o == '-c':
        opts['timeout'] = float(a)
      elif o == '-f':
        opts['filter_codes'] = [int(c) for c in a.split(',')]
      elif o == '-i':
        opts['case_in'] = re.IGNORECASE
      elif o == '-r':
        opts['rptr'] = True
      elif o == '-l':
        opts['logfile'] = a
      elif o == '-v':
        opts['verbose'] = True
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


def main(cmdline):
  sys.stderr.write(f'{BANNER}\n\n')
  check_argc(cmdline)
  parse_cmdline(cmdline)
  check_argv(cmdline)
  check_http_method()
  check_search_place()
  check_auth()

  uris = list(get_uris())
  strings = list(get_strings(opts['searchstr']))

  url_width = 0
  for host in get_hosts(opts['hosts']):
    urls = [host] if 'http' in host else [build_url(host, u) for u in uris]
    for url in urls:
      if len(url) > url_width:
        url_width = len(url)

  with ThreadPoolExecutor(opts['threads']) as exe:
    log('w00t w00t, game started', 'info')
    log('wait bitch, scanning', 'info')
    if opts['verbose']:
      log('\n')
    for host in get_hosts(opts['hosts']):
      urls = [host] if 'http' in host else [build_url(host, u) for u in uris]
      for url in urls:
        for string in strings:
          exe.submit(scan, url, string, url_width)

  if opts['verbose']:
    log('\n\n')
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

