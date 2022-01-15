#!/usr/bin/env python3

import os
import sys
import time
import argparse
from pathlib import Path
from typing import List, Dict, Callable, Any, Set

from binaryninja import *
from bncov import *


# May want to override these defaults
def default_get_seed_from_coverage_file(coverage_filepath: Path) -> Path:
    """Find a seed based on the coverage file's path.

    This example assumes a directory containing testcases is in the same parent
    directory as the coverage dir and that they are named the same except for
    a suffix of "-cov" for the coverage dir and a suffix of ".cov" for the
    coverage file (this is bncov's default naming scheme)."""

    coverage_dir = coverage_filepath.parent
    seed_dir = coverage_dir.parent / coverage_dir.name.replace("-cov", "")
    seed_path = seed_dir / coverage_filepath.stem
    return seed_path


def default_get_metadata(coverage_filepath: Path) -> Dict[str, Any]:
    """Lookup/derive any metadata based on the seed and return it as a dict"""
    source = Path(coverage_filepath).parent
    # AFL structure: corpus dirs like "output/NAME/queue"
    if source.name.startswith("queue"):
        source = source.parent
    metadata = {
        "source": source.name,
    }
    return metadata


class CoverageFile:
    def __init__(
        self,
        path: Path,
        block_coverage: Set[int],
        metadata: Dict[str, Any],
        timestamp: float,
    ):
        self.path = path
        self.block_coverage = block_coverage
        self.metadata = metadata
        self.timestamp = timestamp
        self.extra_blocks: Set[int] = set()


class CoverageTimeline:
    """Houses all the relevant information about the progress of block coverage
    over time: timestamps and block coverage updates.

    This implementation uses a dictionary and tracks individual coverage files
    which is useful when doing analysis based on per-testcase metadata."""

    def __init__(self, bv: binaryninja.BinaryView, covdbs: List[CoverageDB]):
        self.bv = bv
        self.covdbs = covdbs
        self.coverage_timeline: Dict[int, List[CoverageFile]] = {}
        self.block_times: Dict[int, int] = {}
        self.sorted_timestamps: List[int] = []
        self.get_seed_from_coverage_file: Callable[[Path], Path] = default_get_seed_from_coverage_file
        self.get_metadata: Callable[[Path], Dict[str, Any]] = default_get_metadata

    def process_timeline(self):
        """Build up the coverage timeline as a dictionary of coverage deltas"""

        # get timestamps and metadata for all coverage so we can sort on it
        time_coverage_mapping: Dict[float, List[CoverageFile]] = {}
        for covdb in self.covdbs:
            for coverage_file, block_coverage in covdb.trace_dict.items():
                if isinstance(coverage_file, bytes):
                    coverage_file = coverage_file.decode('utf-8')
                coverage_filepath = Path(coverage_file)
                timestamp = self.get_timestamp(coverage_filepath)
                metadata = self.get_metadata(coverage_filepath)
                cur_coverage = CoverageFile(
                    coverage_filepath, block_coverage, metadata, timestamp
                )
                time_coverage_mapping.setdefault(timestamp, []).append(cur_coverage)
        sorted_coverage_files = sorted(
            time_coverage_mapping.items(), key=lambda kv: kv[0]
        )

        # use the sorted list so we only store relevant deltas
        coverage_so_far: Set[int] = set()
        timestamp_zero = sorted_coverage_files[0][0]
        for timestamp, timestamp_coverage_list in sorted_coverage_files:
            for cur_coverage in timestamp_coverage_list:
                coverage_delta = cur_coverage.block_coverage - coverage_so_far
                extra_blocks = cur_coverage.block_coverage - coverage_delta
                if coverage_delta:
                    # reuse instance, just reduce coverage to only the new blocks
                    cur_coverage.block_coverage = coverage_delta
                    cur_coverage.extra_blocks = extra_blocks
                    # Not using sub-second accuracy; group by second
                    time_delta = timestamp - timestamp_zero
                    self.coverage_timeline.setdefault(int(time_delta), []).append(
                        cur_coverage
                    )
                    coverage_so_far.update(coverage_delta)
                    for block_start in coverage_delta:
                        self.block_times[block_start] = time_delta
        self.sorted_timestamps = sorted(self.coverage_timeline)

    def get_timestamp(self, coverage_filepath: Path) -> float:
        """Return a timestamp to establish a relative temporal order for testcases.

        This is a reasonable default, using timestamps from the testcases themselves.

        If you don't have the seeds with their original timestamps, you could do
        something like parse id numbers from AFL-style testcase names."""

        timestamp = os.path.getmtime(self.get_seed_from_coverage_file(coverage_filepath))
        return timestamp

    def print_coverage_over_time(self):
        """List the files and coverage added in time order"""
        for timestamp in self.sorted_timestamps:
            print(f"[*] At timestamp {timestamp}:")
            for coverage_file in self.coverage_timeline[timestamp]:
                filename = coverage_file.path.stem
                blocks_added = len(coverage_file.block_coverage)
                if len(self.covdbs) == 1:
                    print(f'    {blocks_added} new blocks from "{filename}"')
                else:
                    source = coverage_file.metadata["source"]
                    print(f'    {source} added {blocks_added} blocks from "{filename}"')

    def show_function_steps(self):
        bv = self.bv
        func_steps = {}
        for timestamp in self.sorted_timestamps:
            for coverage_file in self.coverage_timeline[timestamp]:
                blocks_added = coverage_file.block_coverage
                funcs_seen = set()
                for block in blocks_added:
                    funcs = bv.get_functions_containing(block)
                    for f in funcs:
                        name = f.name
                        if name not in funcs_seen:
                            funcs_seen.add(name)
                            func_steps[name] = func_steps.get(name, 0) + 1
        for name, steps in sorted(func_steps.items(), key=lambda kv: kv[1], reverse=True):
            print(name, steps)

    def get_coverage_at_timestamp(self, timestamp: int):
        """Return blocks covered up to and including the time of the timestamp arg."""
        coverage_so_far = set()
        for cur_timestamp in self.sorted_timestamps:
            if cur_timestamp > timestamp:
                break
            for cur_coveragefile in self.coverage_timeline[cur_timestamp]:
                coverage_so_far.update(cur_coveragefile.block_coverage)
        return coverage_so_far

    def print_total_coverage_delta(self, func=None):
        """Show difference between the initial coverage and coverage at the end"""
        first_timestamp = self.sorted_timestamps[0]
        initial_coverage = self.get_coverage_at_timestamp(first_timestamp)

        last_timestamp = self.sorted_timestamps[-1]
        final_coverage = self.get_coverage_at_timestamp(last_timestamp)

        if func is not None:
            func_blocks = [block.start for block in func.basic_blocks]
            initial_coverage = initial_coverage.intersection(func_blocks)
            final_coverage = final_coverage.intersection(func_blocks)
            print(f'Phantasm coverage delta for "{func.symbol.short_name}":')
        else:
            print('Phantasm coverage delta:')
        coverage_delta = final_coverage - initial_coverage

        print(f"    First timestamp: {first_timestamp}, {len(initial_coverage)} blocks covered")
        print(f"    Last  timestamp: {last_timestamp}, {len(final_coverage)} blocks covered")
        print(f"    Difference of {len(coverage_delta)} blocks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="The target binary")
    parser.add_argument(
        "coverage_dirs", nargs="+", help="Directories containing coverage files"
    )
    args = parser.parse_args()

    bv = make_bv(args.target, quiet=False)
    covdbs = [
        make_covdb(bv, cur_dir) for cur_dir in args.coverage_dirs
    ]

    timeline = CoverageTimeline(bv, covdbs)
    print("[*] Processing timeline...", end="")
    timeline.process_timeline()
    timeline.print_coverage_over_time()
    #timeline.show_function_steps()
