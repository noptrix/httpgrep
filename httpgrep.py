#!/usr/bin/env python3
# -*- coding: utf-8 -*- ########################################################
#               ____                     _ __                                  #
#    ___  __ __/ / /__ ___ ______ ______(_) /___ __                            #
#   / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                            #
#  /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                             #
#                                           /___/ team                         #
#                                                                              #
# httpgrep                                                                     #
# Scans HTTP servers to find given strings in web URIs.					               #
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
__version__ = '1.0'
__copyright__ = 'santa clause'
__license__ = '1337 h4x0r'


SUCCESS = 0
FAILURE = 1

NORM = '\033[0;37;40m'
BOLD = '\033[1;37;40m'
RED = '\033[1;31;40m'
GREEN = '\033[1;32;40m'
YELLOW = '\033[1;33;40m'
BLUE = '\033[1;34;40m'
MAGENTA = '\033[1;35;40m'

BANNER = '--==[ httpgrep by nullsecurity.net ]==--'
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
                      given URIs, e.g. 'tomcat 8', '/tmp/igot0daysforthese.txt'
  -b <bytes>        - num bytes to read from response. offset == response[0].
                      (default: 64)
  -x <threads>      - num threads for concurrent checks (default: 50)
  -c <seconds>      - num seconds for socket timeout (default: 2.5)
  -i                - use case-insensitive search
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
  'bytes': 64,
  'threads': 50,
  'timeout': 2.5,
  'case_in': False,
  'verbose': False,
}


def log(msg='', _type='normal', esc='\n'):
  iprefix = f'{BOLD}{BLUE}[+] {NORM}'
  gprefix = f'{BOLD}{GREEN}[*] {NORM}'
  wprefix = f'{BOLD}{YELLOW}[!] {NORM}'
  eprefix = f'{BOLD}{RED}[-] {NORM}'
  vprefix = f'{BOLD} - {NORM}'

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
  return


def rptr(ipaddr):
  try:
    return socket.gethostbyaddr(ipaddr)[0]
  except:
    return ipaddr

  return


def get_strings(strings):
  if os.path.isfile(strings):
    with open(strings, 'r', encoding='utf-8') as f:
      for string in f:
        yield string.rstrip()
  else:
      yield strings # single string

  return


def scan(url, ses, searchstr, _bytes, timeout, case_in=False, verbose=False):
  if verbose:
    log(f'scanning {url}', 'verbose')

  r = ses.get(url, timeout=timeout, verify=False)
  res = r.text

  if case_in:
    searchstr = searchstr.lower()
    res = r.text.lower()

  if searchstr in r.text:
    idx = r.text.index(searchstr)
    res = repr(r.text[idx:idx+_bytes])
    log(f'{url} | {searchstr} => {res}', 'good')

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
    _opts, _args = getopt.getopt(sys.argv[1:], 'h:p:tu:s:b:x:c:ivVH')
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
      if o == '-b':
        opts['bytes'] = int(a)
      if o == '-x':
        opts['threads'] = int(a)
      if o == '-c':
        opts['timeout'] = float(a)
      if o == '-i':
        opts['case_in'] = True
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
    for host in get_hosts(opts['hosts']):
      session = requests.Session()
      url = build_url(host, opts['port'], opts['uri'], opts['ssl'])
      for string in get_strings(opts['searchstr']):
        exe.submit(scan, url, session, string, opts['bytes'], opts['timeout'],
          opts['case_in'], opts['verbose'])

  log('n00b n00b, game over', 'info')

  return

if __name__ == '__main__':
  warnings.filterwarnings('ignore')
  main(sys.argv[1:])

