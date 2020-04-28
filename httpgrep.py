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


import sys
import os
import socket
import ipaddress
import requests
import warnings
import getopt
from concurrent.futures import ThreadPoolExecutor, as_completed


__author__ = 'noptrix'
__version__ = '1.7'
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

BANNER = BLUE + '''\
    __    __  __
   / /_  / /_/ /_____  ____ _________  ____
  / __ \/ __/ __/ __ \/ __ `/ ___/ _ \/ __ \\
 / / / / /_/ /_/ /_/ / /_/ / /  /  __/ /_/ /
/_/ /_/\__/\__/ .___/\__, /_/   \___/ .___/
             /_/    /____/         /_/
''' + NORM + '''
     --== [ by nullsecurity.net ] ==--'''

HELP = BOLD + '''usage''' + NORM + '''

  httpgrep -h <args> -s <arg> [opts] | <misc>

''' + BOLD + '''opts''' + NORM + '''

  -h <hosts|file>   - single host or host-range/cidr-range or file containing
                      hosts, e.g.: foobar.net, 192.168.0.1-192.168.0.254,
                      192.168.0.0/24, /tmp/hosts.txt
  -p <port>         - port to connect to (default: 80)
  -t                - use TLS/SSL to connect to service
  -u <URI>          - URI to search given strings in, e.g.: /foobar/, /foo.html
                      (default /)
  -s <string|file>  - a single string or multile strings in a file to find in
                      given URIs and HTTP response headers, e.g.: 'tomcat 8',
                      '/tmp/igot0daysforthese.txt'
  -U <useragent>    - set custom user-agent (default: firefox, rv75, windows)
  -S <where>        - search strings in given places (default: headers,body)
  -b <bytes>        - num bytes to read from response. offset == response[0].
                      (default: 64)
  -x <threads>      - num threads for concurrent checks (default: 80)
  -c <seconds>      - num seconds for socket timeout (default: 2.0)
  -i                - use case-insensitive search
  -r                - perform reverse dns lookup for given IPv4 addresses
  -l <file>         - log urls and found strings to file
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
  'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0',
  'where': ['headers', 'body'],
  'bytes': 64,
  'threads': 80,
  'timeout': 2.0,
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


def scan(url, ses):
  if opts['verbose']:
    log(f'scanning {url}', 'verbose')

  r = ses.get(url, timeout=opts['timeout'], headers={'User-Agent': opts['ua']},
    verify=False)

  if 'body' in opts['where']:
    res = r.text
    if opts['case_in']:
      searchstr = opts['searchstr'].lower()
      res = r.text.lower()
    if searchstr in r.text:
      idx = r.text.index(searchstr)
      res = repr(r.text[idx:idx+opts['bytes']])
      log(f'{url} | body   | {res}', 'good')
      if opts['logfile']:
        log(f'{url} | body   | {res}', 'file')

  if 'headers' in opts['where']:
    for k,v in r.headers.items():
      if searchstr in k or searchstr in v:
        log(f"{url} | header | {k}: {v}", 'good')
        if opts['logfile']:
          log(f"{url} | header | {k}: {v}", 'file')

  return


def build_url(host, port, uri, ssl=False):
  scheme = 'http'
  if ssl:
    scheme = 'https'

  url = f'{scheme}://{host}:{port}{uri}'

  if port == '80' or port == '443':
    url = f'{scheme}://{host}{uri}'

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
      elif '/' in hosts:
        for ipaddr in ipaddress.IPv4Network(hosts).hosts():
          yield rptr(str(ipaddr))
      else:
        yield hosts #single host
  except Exception as err:
    log(err.args[0].lower(), 'error')

  return


def check_argv(cmdline):
  needed = ['-h', '-s', '-V', '-H']

  if '-h' not in cmdline or '-s' not in cmdline or \
    set(needed).isdisjoint(set(cmdline)):
      log('wrong usage, d00d.', 'error')

  return


def parse_cmdline(cmdline):
  global opts

  try:
    _opts, _args = getopt.getopt(sys.argv[1:], 'h:p:tu:s:U:S:b:x:c:irl:vVH')
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
      if o == '-U':
        opts['ua'] = a
      if o == '-S':
        opts['where'] = a.split(',')
        if 'headers' not in opts['where'] and 'body' not in opts['where']:
          log("nope, i only know 'body' and 'headers'", 'error')
      if o == '-b':
        opts['bytes'] = int(a)
      if o == '-x':
        opts['threads'] = int(a)
      if o == '-c':
        opts['timeout'] = float(a)
      if o == '-i':
        opts['case_in'] = True
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

  with ThreadPoolExecutor(opts['threads']) as exe:
    log('w00t w00t, game started', 'info')
    session = requests.Session()
    for host in get_hosts(opts['hosts']):
      url = build_url(host, opts['port'], opts['uri'], opts['ssl'])
      for string in get_strings(opts['searchstr']):
        exe.submit(scan, url, session)

  log('n00b n00b, game over', 'info')

  return


if __name__ == '__main__':
  warnings.filterwarnings('ignore')
  main(sys.argv[1:])

