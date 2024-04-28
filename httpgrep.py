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
import requests
import warnings
import getopt
from concurrent.futures import ThreadPoolExecutor, as_completed


__author__ = 'noptrix'
__version__ = '2.4'
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

BANNER = BLUE + r'''
    __    __  __
   / /_  / /_/ /_____  ____ _________  ____
  / __ \/ __/ __/ __ \/ __ `/ ___/ _ \/ __ \
 / / / / /_/ /_/ /_/ / /_/ / /  /  __/ /_/ /
/_/ /_/\__/\__/ .___/\__, /_/   \___/ .___/
             /_/    /____/         /_/
''' + NORM + '''
     --== [ by nullsecurity.net ] ==--'''

HELP = BOLD + '''usage''' + NORM + '''

  httpgrep -h <args> -s <arg> [opts] | <misc>

''' + BOLD + '''opts''' + NORM + '''

  -h <hosts|file>   - single host/url or host-/cidr-range or file containing
                      hosts or file containing URLs, e.g.: foobar.net,
                      192.168.0.1-192.168.0.254, 192.168.0.0/24, /tmp/hosts.txt
                      NOTE: hosts can also contain ':<port>' on cmdline or in
                      file.
  -p <port>         - port to connect to (default: 80 if hosts were given)
  -t                - use TLS/SSL to connect to service
  -u <URI>          - URI to search given strings in, e.g.: /foobar/, /foo.html
                      (default: /)
  -s <str|file>     - a single string/regex or multile strings/regex in a file
                      to find in given URIs and HTTP response headers,
                      e.g.: 'tomcat 8', '/tmp/igot0daysforthese.txt'
  -S <where>        - search strings in given places (default: headers,body)
  -X <method>       - specify HTTP request method to use (default: get).
                      use '?' to list available methods.
  -a <user:pass>    - http auth credentials (format: 'user:pass')
  -U <UA>           - set custom User-Agent (default: firefox, rv84, windows)
  -b <bytes>        - num bytes to read from response. offset == response[0].
                      (default: 64)
  -x <threads>      - num threads for concurrent scans and checks (default: 80)
  -c <seconds>      - num seconds for socket timeout (default: 3.0)
  -i                - use case-insensitive search
  -r                - perform reverse dns lookup for given IPv4 addresses
                      NOTE: this will slow down the scanz
  -l <file>         - log found matches to file
  -v                - verbose mode (default: quiet)

''' + BOLD + '''misc''' + NORM + '''

  -H                - print help
  -V                - print version information
'''


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


def rptr(ipaddr):
  if opts['rptr']:
    try:
      return socket.gethostbyaddr(ipaddr)[0]
    except:
      return ipaddr

  return ipaddr


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
  r = m(url, timeout=opts['timeout'], headers={'User-Agent': opts['ua']},
    verify=False, auth=opts['auth'])

  return r


def scan(url):
  if opts['verbose']:
    log(f'scanning {url}' + ' ' * 20, 'verbose', esc='\r')
    sys.stdout.flush()

  r = http_req(url)

  if 'body' in opts['where']:
    idx = re.search(opts['searchstr'], r.text, opts['case_in']).regs[0][0]
    if idx:
      res = repr(r.text[idx:idx+opts['bytes']])
      log(f'{url} | body   | {res}', 'good')
      if opts['logfile']:
        log(f'{url} | body   | {res}', 'file')

  if 'headers' in opts['where']:
    for k, v in r.headers.items():
      if re.search(opts['searchstr'], k, opts['case_in']) or \
        re.search(opts['searchstr'], v, opts['case_in']):
        log(f"{url} | header | {k}: {v}", 'good')
        if opts['logfile']:
          log(f"{url} | header | {k}: {v}", 'file')

  if opts['verbose']:
    sys.stdout.flush()
    log('\n')

  return


def build_url(host):
  scheme = 'http'
  if opts['ssl']:
    scheme = 'https'

  if ':' in host:
    return f'{scheme}://{host}{opts["uri"]}'

  url = f'{scheme}://{host}:{opts["port"]}{opts["uri"]}'

  return url


def get_hosts(hosts):
  try:
    if os.path.isfile(hosts):
      with open(hosts, 'r', encoding='utf-8') as f:
        for host in f:
          yield host.rstrip()
    else:
      if '-' in hosts:
        start = ipaddress.IPv4Address(hosts.split('-')[0])
        end = ipaddress.IPv4Address(hosts.split('-')[1])
        for i in range(int(start), int(end) + 1):
          ipaddr = str(ipaddress.IPv4Address(i))
          yield rptr(str(ipaddr))
      elif '/' in hosts and 'http' not in hosts:
        for ipaddr in ipaddress.IPv4Network(hosts).hosts():
          yield rptr(str(ipaddr))
      else:
        yield hosts # single host or url
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
    _opts, _args = getopt.getopt(sys.argv[1:], 'h:p:tu:s:S:X:a:U:b:x:c:irl:vVH')
    for o, a in _opts:
      if o == '-h':
        opts['hosts'] = a
      if o == '-p':
        opts['port'] = a
      if o == '-t':
        opts['ssl'] = True
      if o == '-u':
        opts['uri'] = a
      if o == '-s':
        opts['searchstr'] = a
      if o == '-S':
        opts['where'] = a.split(',')
      if o == '-X':
        opts['method'] = a
      if o == '-a':
        opts['auth'] = tuple(a.split(':', 1))
      if o == '-U':
        opts['ua'] = a
      if o == '-b':
        opts['bytes'] = int(a)
      if o == '-x':
        opts['threads'] = int(a)
      if o == '-c':
        opts['timeout'] = float(a)
      if o == '-i':
        opts['case_in'] = re.IGNORECASE
      if o == '-r':
        opts['rptr'] = True
      if o == '-l':
        opts['logfile'] = a
      if o == '-v':
        opts['verbose'] = True
      if o == '-V':
        log(f'httpgrep v{__version__}', _type='info')
        sys.exit(SUCCESS)
      if o == '-H':
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

  with ThreadPoolExecutor(opts['threads']) as exe:
    log('w00t w00t, game started', 'info')
    log('wait bitch, scanning', 'info')
    if opts['verbose']:
      log('\n')
    for host in get_hosts(opts['hosts']):
      url = host
      if 'http' not in host:
        url = build_url(host)
      for string in get_strings(opts['searchstr']):
        exe.submit(scan, url)

  if opts['verbose']:
    log('\n\n')
  log('n00b n00b, game over', 'info')

  return


if __name__ == '__main__':
  warnings.filterwarnings('ignore')
  try:
    main(sys.argv[1:])
  except KeyboardInterrupt:
    log('\n')
    log('you aborted me', 'warn')
    os._exit(SUCCESS)

