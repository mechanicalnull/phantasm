'''
Render an HTML visualization of coverage over time using SVG and Javascript.

Based on the original idea from the export_svg example
https://github.com/Vector35/binaryninja-api/blob/master/python/examples/export_svg.py
'''

import sys
from datetime import datetime

from pathlib import Path

from binaryninja import *


escape_table = {
    "'": "&#39;",
    ">": "&#62;",
    "<": "&#60;",
    '"': "&#34;",
    ' ': "&#160;"
}


def escape(toescape):
    # handle extended unicode
    toescape = toescape.encode('ascii', 'xmlcharrefreplace')
    # still escape the basics
    if sys.version_info[0] == 3:
        return ''.join(escape_table.get(chr(i), chr(i)) for i in toescape)
    else:
        return ''.join(escape_table.get(i, i) for i in toescape)


def generate_css(function, timeline):

    css_path = Path(__file__).parent / 'anim.css'
    with open(css_path.as_posix(), 'r') as f:
        css_content = f.read()

    return css_content


def generate_svg(name, graph):
    """Build SVG XML for the given function.
    
    NOTE: there's some unlabeled magic constants in here from the original
          example, I haven't yet taken time to experiment and name all of them.
    """

    heightconst = 15
    ratio = 0.48
    widthconst = heightconst * ratio

    output = '''        <svg id="anim_graph" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 {width} {height}">
        <defs>
            <marker id="arrow-TrueBranch" class="arrow TrueBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
            <marker id="arrow-FalseBranch" class="arrow FalseBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
            <marker id="arrow-UnconditionalBranch" class="arrow UnconditionalBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
            <marker id="arrow-IndirectBranch" class="arrow IndirectBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" />
            </marker>
        </defs>
    '''.format(width=graph.width * widthconst + 20, height=graph.height * heightconst + 20)

    output += f'''    <g id="functiongraph">'''
    edges = ''

    for i, block in enumerate(graph):
        # Calculate basic block location and coordinates
        x = ((block.x) * widthconst)
        y = ((block.y) * heightconst)
        width = ((block.width) * widthconst)
        height = ((block.height) * heightconst)

        # Render block
        bb_id = f'bb-{block.basic_block.start:x}'
        output += '        <g>\n'
        # We're going to override block colors with .basicblock default and CSS animation, so we omit fill color for each block
        output += f'            <rect id="{bb_id}"" class="basicblock" x="{x}" y="{y}" fill-opacity="0.4" height="{height+12}" width="{width+16}"/>\n'

        output += '            <text x="{x}" y="{y}">\n'.format(x=x, y=y + (i + 1) * heightconst)
        for i, line in enumerate(block.lines):
            line_str = '                <tspan id="instr-{address}" x="{x}" y="{y}">'
            line_str = line_str.format(x=x + 6, y=y + 6 + (i + 0.7) * heightconst, address=hex(line.address)[:-1])
            output += line_str
            for token in line.tokens:
                token_str = '<tspan class="{tokentype}">{text}</tspan>'
                token_str = token_str.format(text=escape(token.text), tokentype=InstructionTextTokenType(token.type).name)
                output += token_str
            output += '</tspan>\n'
        output += '            </text>\n'
        output += '        </g>\n'

        # Edges are rendered in a separate chunk so they have priority over the
        # basic blocks or else they'd render below them
        for edge in block.outgoing_edges:
            points = ""
            x, y = edge.points[0]
            points += str(x * widthconst) + "," + \
                str(y * heightconst + 12) + " "
            for x, y in edge.points[1:-1]:
                points += str(x * widthconst) + "," + \
                    str(y * heightconst) + " "
            x, y = edge.points[-1]
            points += str(x * widthconst) + "," + \
                str(y * heightconst + 0) + " "
            if edge.back_edge:
                edges += '        <polyline class="back_edge {type}" points="{points}" marker-end="url(#arrow-{type})"/>\n'.format(
                    type=BranchType(edge.type).name, points=points)
            else:
                edges += '        <polyline class="edge {type}" points="{points}" marker-end="url(#arrow-{type})"/>\n'.format(
                    type=BranchType(edge.type).name, points=points)

    output += ' ' + edges + '\n'
    output += '    </g>\n'
    output += '</svg>'

    return output


def get_graph(func, show_opcodes, show_addresses):
    """Get a graph from the Binary Ninja Function object for rendering"""
    settings = DisassemblySettings()
    if show_opcodes:
        settings.set_option(DisassemblyOption.ShowOpcode, True)
    if show_addresses:
        settings.set_option(DisassemblyOption.ShowAddress, True)
    graph_type = FunctionGraphType.NormalFunctionGraph
    graph = func.create_graph(graph_type=graph_type, settings=settings)
    graph.layout_and_wait()

    return graph

def generate_js(func, timeline):
    func_blocks = set(bb.start for bb in func.basic_blocks)
    timeline_array = []
    array_index = 0
    for timestamp in timeline.sorted_timestamps:
        for coverage_file in timeline.coverage_timeline[timestamp]:
            seed_name = coverage_file.path.stem
            new_blocks = func_blocks.intersection(coverage_file.block_coverage)
            extra_blocks = func_blocks.intersection(coverage_file.extra_blocks)
            if len(new_blocks) == 0:
                continue
            blocks_added = '[' + ','.join(f'"bb-{block_addr:x}"' for block_addr in new_blocks) + ']'
            extra_block_str = '[' + ','.join(f'"bb-{block_addr:x}"' for block_addr in extra_blocks) + ']'
            js_seed_obj = (
                f'{{ "name": "{seed_name}", "blocks": {blocks_added}, ' +
                f'"index": {array_index}, "time": {timestamp}, "extras": {extra_block_str} }}'
            )
            timeline_array.append(js_seed_obj)
            array_index += 1

    js_str = 'let seeds = [' + ', '.join(timeline_array) + '];\n'

    anim_path = Path(__file__).parent / 'anim.js'
    with open(anim_path.as_posix()) as f:
        anim_str = f.read()
    js_str += anim_str

    return js_str


def get_embedded_js():
    js = ''
    cur_path = Path(__file__)

    svg_pan_zoom_path = cur_path.parent.parent / 'svg-pan-zoom' / 'svg-pan-zoom.min.js'
    with open(svg_pan_zoom_path.as_posix(), 'r') as f:
        svg_pan_zoom_js = f.read()
    js += svg_pan_zoom_js

    return js


def generate_footer(func_name, filename):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    description = f'Coverage of "{func_name}" from {filename} at {timestamp}.'

    phantasm_link = '<a href="https://github.com/mechanicalnull/phantasm">Phantasm</a> by @mechanicalnull'
    bn_link = '<a href="https://binary.ninja/">Binary Ninja</a>'
    cred = f'Generated by {phantasm_link}, using {bn_link}.'

    footer = f'<p>{description} {cred}</p>'
    return footer


def generate_html(bv, func, timeline, show_opcodes=False, show_addresses=False):
    """Build and save an HTML document showing coverage over time"""

    func_name = func.symbol.short_name

    css = generate_css(func, timeline)
    graph = get_graph(func, show_opcodes, show_addresses)
    svg = generate_svg(func_name, graph)
    embedded_js = get_embedded_js()
    js = generate_js(func, timeline)
    footer = generate_footer(func_name, os.path.basename(bv.file.original_filename))

    content = f'''<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>Phantasm {func_name}</title>
        <style type="text/css">
{css}
        </style>
        <script>
{embedded_js}
        </script>
        <script defer>
{js}
        </script>
    </head>
    <body onload="init_anim()">
<div id="header">
    <ul class="button-group">
        <li><button id="play_button" type="button" class="button">Play/Pause</button></li>
        <li><button id="loop_button" type="button" class="button">Loop Animation</button></li>
        <li><button id="prev_button" type="button" class="button">Prev</button></li>
        <li><button id="next_button" type="button" class="button">Next</button></li>
    </ul>
    <input type="range" id="slider">
    <button id="highlight_cur_button" type="button" class="button">Highlight Current</button></li>
    <span>Seed Index: </span>
    <span id="cur_frame_span">0</span>/<span id="max_frame_span"></span>,
    <span id="cur_seed_span"></span>
</div>
<div id="content">
{svg}
</div>
<div id="footer">
{footer}
</div>
    </body>
</html>
'''
    return content
