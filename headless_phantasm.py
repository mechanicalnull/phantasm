#!/usr/bin/env python3

'''
Demonstrating Headless use of Phantasm.

Note that this requires a Binary Ninja license that supports headless operation.
Otherwise just enjoy using the plugin via the GUI and builtin Python console.

Example Usage:
python3 headless_phantasm.py test/cgc/rematch-crackaddr main test/cgc/queue{,-cov}
'''

import sys
import argparse
from pathlib import Path

parent_dir = Path('.').absolute().parent
sys.path.insert(0, parent_dir.as_posix())

from phantasm.phantasm.plugin import graph_coverage
from bncov import get_bv


if __name__ == "__main__":

    parser = argparse.ArgumentParser('headless_phantasm')
    parser.add_argument('target', help='Target binary or BNDB')
    parser.add_argument('function', help='Target function to graph')
    parser.add_argument('corpus_dir', help='Dir containing inputs with timestamps')
    parser.add_argument('coverage_dir', help='Dir containing coverage information for inputs')
    parser.add_argument('--output_file', help='Where to save the file (default: current dir, auto-named)')
    parser.add_argument('--show_opcodes', type=bool, default=True,
                        help='Don\'t show opcodes in graph (default: shown)')
    parser.add_argument('--show_addrs', type=bool, default=True,
                        help='Don\'t show addresses in graph (default: shown)')
    args = parser.parse_args()

    bv = get_bv(args.target, quiet=False)

    print(f'[*] Invoking graph_coverage on {args.function}')
    output_file = graph_coverage(
        bv,
        args.function,
        args.corpus_dir,
        args.coverage_dir,
        args.output_file,
        args.show_opcodes
    )
