# MIT License
#
# Copyright (c) 2017 Tom Melo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE

#!/usr/bin/env python
# -*- coding: utf-8; mode: python; py-indent-offset: 4; indent-tabs-mode: nil -*-
# vim: fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4
# pylint: disable=C0103,C0301,W1202,W0212

"""
dnsrato is a DNS reconnaissance tool that performs a brute force
sub-domain enumeration based on a word list file.

This is a Python version(with some extra features) of the first version
written in C by Ricardo Longatto.
The C version can be found at: https://github.com/ricardolongatto/dnsrato
"""

import argparse
import sys
import os
import time
import socket
import ssl
import logging
import random
import json
from concurrent.futures import ThreadPoolExecutor
from mmap import mmap
from xml.dom.minidom import parseString
from collections import namedtuple
from colorama import Fore
from colorama import init
from tqdm import tqdm
from tld import get_tld
from tld.exceptions import TldDomainNotFound, TldBadUrl, TldIOError
from dicttoxml import dicttoxml
from whois import whois

logging.basicConfig(format="%(message)s")
log = logging.getLogger("dnsrato")

DNSLookupParams = namedtuple("DNSLookupParams", "tld preffix port use_ssl sleep timeout progress")
DNSEnumResult = namedtuple('DNSEnumResult', 'tld subdomains whois_record out_format out_file')
subdomains = []
whois_record = dict()

init(autoreset=True)
VERSION = "v1.1.0"
BANNER = r"""
         ____
        |    |
        |____|
       _|____|_ 
        /  ee`. 
      .<     __O
     /\ \.-." \  
    J  `.|`.\/ \ 
    | |_.|  | | |
     \__."`.|-" /
     L   /|o`--"\ 
     |  /\/\/\   \           
     J /      `.__\\
     |/         /  \          dnsrato
      \\      ."`.  `.     v1.1.0 [tommelo] ."
    ____)_/\_(____`.  `-._________________."/
   (___._/  \_.___) `-.__________________.-"
"""

LOG_FORMAT = '[+] {0:17}{1}'
TEXT_OUTPUT_FORMAT = "Domain: {}\nWhois Lookup\n{}\nSubdomain Lookup\n{}"
UNDERLINED_FORMAT = '\033[4m{}\033[0m'
SUPPORTED_FORMATS = ('xml', 'json', 'text')
USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
]

parser = argparse.ArgumentParser(
    prog="dnsrato",
    usage="dnsrato <options>")
parser.add_argument("-d", "--domain", metavar="", required=True, help="the domain url")
parser.add_argument("-D", "--dictionary", metavar="", help="the dictionary file")
parser.add_argument("-f", "--format", metavar="", help="the output format(text, json or xml)")
parser.add_argument("-o", "--output", metavar="", help="the output file")
parser.add_argument("-p", "--port", metavar="", help="the port number", type=int)
parser.add_argument("-s", "--sleep", metavar="", help="thread sleep", type=int)
parser.add_argument("-w", "--workers", metavar="", help="thread workers", type=int)
parser.add_argument("-t", "--timeout", metavar="", help="the request timeout", type=int)
parser.add_argument("-v", "--verbose", action="store_true", help="enables the verbose mode")
parser.add_argument("--proxy", action="store_true", help="enables socks5 proxy")
parser.add_argument("--proxy-host", metavar="", help="socks5 proxy host")
parser.add_argument("--proxy-port", metavar="", help="socks5 proxy port", type=int)
parser.add_argument("--ssl", action="store_true", help="enables ssl")
parser.add_argument("--version", action="version", version=VERSION)

parser.set_defaults(port=80)
parser.set_defaults(output=None)
parser.set_defaults(format="text")
parser.set_defaults(dictionary="rato.txt")
parser.set_defaults(sleep=0)
parser.set_defaults(timeout=4)
parser.set_defaults(threads=10)
parser.set_defaults(proxy_host="127.0.0.1")
parser.set_defaults(proxy_port=9150)

def is_piped_input():
    """
    Checks the piped input.

    This function checks if this script
    is being executed with a piped input.

    E.g.: echo domain.com | python dnsrato.py

    Returns
    -------
    bool
        True if the is a piped input, False otherwise.
    """
    return not sys.stdin.isatty()

def is_piped_output():
    """
    Checks the piped output.

    This function checks if this script
    is being executed with a piped output.

    E.g.: python dnsrato.py -d domain.com --format json > outfile.json

    Returns
    -------
    bool
        True if the is a piped output, False otherwise.
    """
    return not sys.stdout.isatty()

def file_lines(dictionary_file):
    """
    Counts the number of lines of the given file.

    Parameters
    -------
    dictionary_file: file
        The text file

    Returns
    -------
    int
        The number of lines of the given file
    """
    buf = mmap(dictionary_file.fileno(), 0)
    lines = 0
    readline = buf.readline
    while readline():
        lines += 1
    return lines

def is_host_alive(domain, port, use_ssl):
    """
    Checks if the given host is up.

    The test to determine if the host is up consists
    in openning a connection to the given host and port.
    If no error occurs during the connection process the host will
    be considered up and running.

    Parameters
    -------
    domain: str
        The top level domain url
    port: int
        The host port
    use_ssl: bool
        Enables SSL mode

    Returns
    -------
    bool
        True if the the host is up, False otherwise.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_ssl:
            sock = ssl.wrap_socket(sock)

        sock.connect((domain, port))
        sock.close()
        return True
    except socket.error as error:
        log.info(Fore.RED + "[!] " + error.strerror)
        return False

def dns_lookup(config):
    """
    Checks if a subdomain exists.

    To determine if a subdomain is valid, a Http HEAD
    request will be sent to the given host/port.
    If no error occurs during the request, the subdomain
    will be considered valid and it will be saved to the
    subdomains array.

    Parameters
    -------
    config: DNSLookupParams
        The parameters to perform a dns lookup.
        E.g.:
            DNSLookupParams(
                tld='domain.com',
                preffix='dashboard.',
                port=80,
                use_ssl=False,
                sleep=0,
                timeout=4,
                progress=progress_bar)
    """
    subdomain = config.preffix + config.tld
    try:
        socket.setdefaulttimeout(config.timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if config.use_ssl:
            sock = ssl.wrap_socket(sock)
        sock.connect((subdomain, config.port))
        sock.send("HEAD / HTTP/1.1\r\n")
        sock.send("HOST: {}\r\n".format(subdomain))
        sock.send("User-Agent: {}\r\n".format(random.choice(USER_AGENTS)).encode("utf-8"))
        sock.send("\r\n")
        sock.close()

        if not is_piped_output() and log.isEnabledFor(logging.DEBUG):
            config.progress.write(LOG_FORMAT.format('Found:', Fore.GREEN + subdomain))

        subdomains.append(subdomain)
    except socket.error:
        pass

    config.progress.update(1)
    if config.sleep > 0:
        time.sleep(config.sleep)

def whois_lookup(domain):
    """
    Performs a whois lookup.

    Parameters
    -------
    domain: str
        The domain
    """
    try:
        result = whois(domain)
    except socket.error:
        log.info(Fore.YELLOW + '[!] Unable to perform a whois lookup' + Fore.RESET)

    attrs = result._regex or vars(result).get('_regex')
    for attr in attrs:
        value = result.__getattr__(attr)
        if isinstance(value, list):
            whois_record[attr] = []
            log.info('[+] ' + attr + ':')
            for item in value:
                item = item.encode('utf-8')
                whois_record[attr].append(item)
                log.info(LOG_FORMAT.format('', item))
        else:
            whois_record[attr] = value
            log.info(LOG_FORMAT.format(attr + ':', value))

def flush_output(result):
    """
    Flushes the result to the output.

    The formats json and xml will be ignored if the output
    is 'stdout' and the execution is not being piped.

    Parameters
    -------
    result: DNSEnumResult
        The enumeration result
    """

    # outputs the result in text format
    if result.out_format == "text":
        out = TEXT_OUTPUT_FORMAT.format(
            result.tld,
            "\n".join(['%s: %s' % (key, value) for (key, value) in result.whois_record.items()]),
            "\n".join(result.subdomains))

        if result.out_file:
            with open(result.out_file, "w") as outfile:
                outfile.write(out)

        if is_piped_output():
            sys.stdout.write(out)
            sys.stdout.flush()

    # outputs the result in json format
    if result.out_format == "json":
        out = {"domain": result.tld, "subdomains": result.subdomains, "whois": result.whois_record}
        if result.out_file:
            with open(result.out_file, "w") as outfile:
                json.dump(out, outfile, indent=2, sort_keys=True)

        if is_piped_output():
            sys.stdout.write(json.dumps(out, indent=2, sort_keys=True))
            sys.stdout.flush()

    # outputs the result in xml format
    if result.out_format == "xml":
        out = {"domain": result.tld, "subdomains": result.subdomains, "whois": result.whois_record}
        xml = dicttoxml(out, custom_root="dns", attr_type=False)
        dom = parseString(xml)
        if result.out_file:
            with open(result.out_file, "w") as outfile:
                outfile.write(dom.toprettyxml())

        if is_piped_output():
            sys.stdout.write(dom.toprettyxml())
            sys.stdout.flush()

def execute(args):
    """
    Executes a DNS lookup.

    Parameters
    -------
    args: argparse.Namespace
        The cli arguments
    """
    if args.verbose and not is_piped_output():
        log.setLevel(logging.DEBUG)

    try:
        top_level_domain = get_tld(args.domain, fix_protocol=True)
    except (TldDomainNotFound, TldBadUrl, TldIOError):
        log.info(Fore.RED + "[!] Invalid domain url: {}".format(args.domain))
        sys.exit(1)

    if not args.format in SUPPORTED_FORMATS:
        log.info(Fore.RED + "[!] Invalid format option: {}".format(args.format))
        sys.exit(1)

    if args.proxy:
        try:
            import socks
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, args.proxy_host, args.proxy_port)
            socket.socket = socks.socksocket
        except ImportError:
            log.info(Fore.RED + "[!] Unable to configure the proxy")
            sys.exit(1)

    if not is_host_alive(top_level_domain, args.port, args.ssl):
        log.info(Fore.RED + "[!] Unable to connect to host: {}".format(top_level_domain))
        sys.exit(1)

    if not os.path.isfile(args.dictionary):
        log.info(Fore.RED + "[!] File {} not found".format(args.dictionary))
        sys.exit(1)

    log.info(BANNER)
    log.info(LOG_FORMAT.format('Domain:', top_level_domain))
    log.info(LOG_FORMAT.format('Host status:', Fore.GREEN + "UP" + Fore.RESET))
    log.info('[*]')
    log.info('[+] ' + UNDERLINED_FORMAT.format('Whois Lookup'))

    whois_lookup(top_level_domain)

    log.info('[*]')
    log.info('[+] ' + UNDERLINED_FORMAT.format('Subdomain Lookup'))
    pool = ThreadPoolExecutor(max_workers=args.workers)
    with open(args.dictionary, "r+") as dictionary_file:
        lines = file_lines(dictionary_file)
        progress_bar = tqdm(total=lines)
        for line in dictionary_file:
            params = DNSLookupParams(
                tld=top_level_domain,
                preffix=line.strip(),
                port=args.port,
                use_ssl=args.ssl,
                sleep=args.sleep,
                timeout=args.timeout,
                progress=progress_bar)
            pool.submit(dns_lookup, params)

    pool.shutdown(wait=True)

    if not is_piped_output() and log.isEnabledFor(logging.DEBUG):
        progress_bar.write("[*]")
        progress_bar.write("[+] Enumeration process finished")
        progress_bar.write("[+] Flushing the output")
        progress_bar.write("[+] Bye")
        progress_bar.write("")

    result = DNSEnumResult(
        tld=top_level_domain,
        subdomains=subdomains,
        whois_record=whois_record,
        out_format=args.format,
        out_file=args.output)

    progress_bar.close()
    flush_output(result)
    sys.exit()

if __name__ == "__main__":
    try:
        if is_piped_input():
            url = sys.stdin.read().strip()
            cli_args = argparse.Namespace(
                domain=url,
                verbose=False,
                proxy=False,
                proxy_host="127.0.0.1",
                proxy_port=9150,
                sleep=0,
                timeout=4,
                workers=10,
                ssl=False,
                port=80,
                output=None,
                format="text",
                dictionary="rato.txt")
        else:
            cli_args = parser.parse_args()

        execute(cli_args)
    except KeyboardInterrupt:
        log.info("\n[+] User requested to stop")
        log.info("[+] Flushing the output")
        domain_arg = get_tld(cli_args.domain, fix_protocol=True)
        current = DNSEnumResult(
            tld=domain_arg,
            subdomains=subdomains,
            whois_record=whois_record,
            out_format=cli_args.format,
            out_file=cli_args.output)
        flush_output(current)
        log.info("[+] Bye")
        os._exit(0)
