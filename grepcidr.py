import argparse
import ipaddress
import os
import re
import sys

class GrepCIDR:
    """Search lines for IP addresses within CIDRs"""

    def __init__(self, _args):

        self._args = _args
        self._needles   = []

        self._format = '{2}'
        if args.show_pattern:
            self._format = '{1};{2}'
        if not args.no_file:
            self._format = f"{{0}};{self._format}"

        self.add_needles_from_files(args.needle_file)
        self.add_needles_from_str(args.needle_str)

    def open_file(self, f):
        return sys.stdin if f == '-' else open(f, 'r', encoding='utf-8')

    def add_needle(self, needle):
        try:
            self._needles.append(ipaddress.ip_network(needle))
        except ValueError as e:
            if args.debug:
                print("{program}: {error}, skipping this in line: `{line}'".format(
                    program=os.path.basename(sys.argv[0]), line=line, error=e), file=sys.stderr)

    def add_needles_from_files(self, needles):

        if not needles:
            return

        needles = [needles] if isinstance(needles, str) else needles

        for needle in needles:
            with self.open_file(needle) as f:
                for line in f:
                    for match in filter(None, re.split(r"\s+", line)):
                        self.add_needle(match)

    def add_needles_from_str(self, needles):

        if not needles:
            return

        needles = [needles] if isinstance(needles, str) else needles

        for needle in needles:
            self.add_needle(needle)


    def check(self, haystack, element, line):
        try:
            ip = ipaddress.ip_address(element)
        except ValueError as e:
            if args.debug:
                print("{program}: {error}, skipping this in line: `{line}'".format(
                    program=os.path.basename(sys.argv[0]), error=e, line=line), file=sys.stderr)
            return
        for net in self._needles:
            if ip in net:
                print(self._format.format(haystack, net, element if self._args.only_ip else line.rstrip()))

    def search(self):
        if self._args.file:
            for haystack in self._args.file:
                with self.open_file(haystack) as f:
                    for line in f:
                        for match in filter(None, re.split(r"\s+", line)):
                            self.check(haystack, match, line)

        if self._args.haystack_str:
            for line in self._args.haystack_str:
                for match in filter(None, re.split(r"\s+", line)):
                    self.check("<arg>", match, line)


if __name__ == '__main__':

    argp = argparse.ArgumentParser()
    argp.add_argument('file', nargs='*', help='file with IP addresses to search')
    argp.add_argument('-E', action='append', dest='haystack_str', help='IP addresses to search as strings')
    argp.add_argument('-f', action='append', dest='needle_file', help='file with CIDRs')
    argp.add_argument('-e', action='append', dest='needle_str', help='CIDRs as strings')
    argp.add_argument('-p', action='store_true', dest='show_pattern', help='include pattern that matched in the output')
    argp.add_argument('-o', action='store_true', dest='only_ip', help='output the matching IP address only, not the whole line')
    argp.add_argument('--no-file', action='store_true', dest='no_file', help='don\'t output matching file name')
    argp.add_argument('--debug', action='store_true', dest='debug', help='print debugging output')
    args = argp.parse_args()

    if not args.file and not args.haystack_str:
        argp.error('file or pattern to search is required')

    if not args.needle_file and not args.needle_str:
        argp.error('CIDR file or pattern is required')

    grepcidr = GrepCIDR(args)
    grepcidr.search()
