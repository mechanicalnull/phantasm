# Phantasm - Binary Ninja plugin for visualizing fuzzing coverage over time

Phantasm builds an interactive visualization of how fuzzing increases coverage
of a function over time. Using coverage abstraction from the plugin
[bncov](https://github.com/ForAllSecure/bncov), and building on Vector35's
[export SVG example](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/export_svg.py),
Phantasm adds the aspect of exploring time via a single-page HTML visualization
that users can use to explore how the addition of each seed over time changes
the coverage of the function.

![Phantasm Demo](/images/phantasm_demo.gif)

Users can pan and zoom around the graph in their browser, as well as either
watch a loop or step through each seed as it is added. This is currently a proof
of concept, please open an issue if you have more ideas.

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

For those that want to see results before trying it, the repository includes
an [example output](/test/example-output.html) that should display even on
systems without Binary Ninja installed.
