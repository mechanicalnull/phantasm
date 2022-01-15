#!/usr/bin/env python3

'''
Demonstrating Headless use of Phantasm.

Note that this requires a Binary Ninja license that supports headless operation.
Otherwise just enjoy using the plugin via the GUI and builtin Python console.

Example Usage (make sure you heed warnings about timestamps and save and restore
timestamps via something like tar archives):
python3 headless_phantasm.py test/cgc/rematch-crackaddr main test/cgc/queue{,-cov}
'''

import sys
import argparse
import time
from binaryninja import BinaryViewType


from phantasm.plugin import graph_coverage


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

    sys.stdout.write("[B] Loading Binary Ninja view of \"%s\"... " % args.target)
    sys.stdout.flush()
    start = time.time()
    bv = BinaryViewType.get_view_of_file(args.target)
    print("finished in %.02f seconds" % (time.time() - start))

    print(f'[*] Invoking graph_coverage on {args.function}')
    output_file = graph_coverage(
        bv,
        args.function,
        args.corpus_dir,
        args.coverage_dir,
        args.output_file,
        args.show_opcodes
    )
