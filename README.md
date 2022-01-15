# Phantasm - Binary Ninja plugin for visualizing fuzzing coverage over time

Phantasm builds an interactive visualization of how fuzzing increases coverage
of a function over time. Using coverage abstraction from the plugin
[bncov](https://github.com/ForAllSecure/bncov), Phantasm adds the aspect of time
and writes a single-page HTML visualization that users can use to see how the
addition of each seed over time changes the coverage of the function.

![Phantasm Demo](/images/phantasm_demo.gif)

## Install

Just clone this repo to your plugins directory.

## Usage

1. Navigate in Binary Ninja to the function you want to visualize coverage over
   time for.
2. Use the context menu to select Phantasm -> Animate Current Function.
3. Fill in the dialog (description of key fields below).
4. Open the output file in a browser. Any errors will be written to the log in
   Binary Ninja

- Corpus Directory: where the input files are stored (NOTE: the inputs files are
  only used for their timestamps, make sure you either use the original
  directory or have copied the files around in a manner that preserves
  timestamps, such as `cp -pr src dst`).
- Coverage Directory: directory containing files in drcov or module+offset
  format.
- Output File: where to save the HTML output
