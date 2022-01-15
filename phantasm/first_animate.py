# from binaryninja import *
import os
import time
import sys

from pathlib import Path
from urllib.request import pathname2url

from binaryninja.interaction import get_save_filename_input, show_message_box, TextLineField, ChoiceField, SaveFileNameField, get_form_input
from binaryninja.settings import Settings
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult, InstructionTextTokenType, BranchType, DisassemblyOption, FunctionGraphType
from binaryninja.function import DisassemblySettings
from binaryninja.plugin import PluginCommand

colors = {'green': [162, 217, 175], 'red': [222, 143, 151], 'blue': [128, 198, 233], 'cyan': [142, 230, 237], 'lightCyan': [
    176, 221, 228], 'orange': [237, 189, 129], 'yellow': [237, 223, 179], 'magenta': [218, 196, 209], 'none': [74, 74, 74],
    'disabled': [144, 144, 144]}

escape_table = {
    "'": "&#39;",
    ">": "&#62;",
    "<": "&#60;",
    '"': "&#34;",
    ' ': "&#160;"
}


def gray_to_red(block_start, frame_num, total_frames, duration):
    """New blocks pop up as red, stay red"""
    bb_id = f"bb-{block_start:x}"
    start_percent = frame_num / total_frames * 100
    next_percent = (frame_num + 1) / total_frames * 100
    # this animation transitions fill from gray to red between start frame and next frame
    animation_css = f"""
            @keyframes anim-{bb_id} {{
				0%, {start_percent:.4f}% {{ fill: #4a4a4a; }}
				{next_percent:.4f}%, 100% {{ fill: #ff0000; }}
			}}
			#{bb_id} {{ animation: {duration}s linear infinite anim-{bb_id}; }}"""
    return animation_css


def gray_red_blue(block_start, frame_num, total_frames, duration):
    """New blocks pop red, stay red, then fade to blue"""
    bb_id = f"bb-{block_start:x}"
    delay_at_end = 1  # amount of time to freeze at end

    red_duration_seconds = 1
    red_duration_frame_percent = red_duration_seconds / (duration - delay_at_end) * 100
    blue_to_red_duration_seconds = 1
    blue_to_red_frame_percent = blue_to_red_duration_seconds / (duration - delay_at_end) * 100
    # artificially expand total_frames to account for delay at end
    total_frames *= duration / (duration - delay_at_end)

    gray_stop_percent = max(0, frame_num - 1) / total_frames * 100
    red_start_percent = frame_num / total_frames * 100
    red_stop_percent = red_start_percent + red_duration_frame_percent
    blue_start_percent = min(red_stop_percent + blue_to_red_frame_percent, 100)

    animation_css = f"""
            @keyframes anim-{bb_id} {{
				0%, {gray_stop_percent:.4f}% {{ fill: #4a4a4a; }}
				{red_start_percent:.4f}%, {red_stop_percent:.4f}% {{ fill: #ff0000; }}
				{blue_start_percent:.4f}%, 100% {{ fill: #0000ff; }}
			}}
			#{bb_id} {{ animation: {duration}s ease-in-out infinite anim-{bb_id}; }}"""
    return animation_css


def get_animation_for_block(
    block_start: int, 
    frame_num: int, 
    total_frames: int, 
    duration: int=5,
):
    """Generate CSS to pop a block from gray to red at the right frame
    
    block_start: int
    frame_num: int
    total_frames: int
    duration: int # seconds"""
    animation_function = gray_red_blue
    return animation_function(block_start, frame_num, total_frames, duration)


def get_custom_css(
    timeline: "CoverageTimeline", 
    function: "binaryninja.function.Function",
    frame_for_empty_update: bool=False,
):
    """Generate animation CSS to highlight the graph to show coverage over time"""

    animation_css = "/* start animation CSS */"
    func_blocks = set(block.start for block in function.basic_blocks)

    # show frames for empty updates to represent time elapsed
    # This isn't really time elapsed, just timestamps where
    # functions other than this one got updated
    if frame_for_empty_update:
        num_total_frames = len(timeline.sorted_timestamps)
    else:
        num_total_frames = 0
        for timestamp in timeline.sorted_timestamps:
            if any(
                func_blocks.intersection(cov_file.block_coverage) 
                for cov_file in timeline.coverage_timeline[timestamp]
            ):
                num_total_frames += 1
    for i, cur_timestamp in enumerate(timeline.sorted_timestamps):
        new_blocks = set()
        for cur_coverage_file in timeline.coverage_timeline[cur_timestamp]:
            # Using the fact that the coverage_timeline should only include deltas here
            cur_func_blocks = func_blocks.intersection(cur_coverage_file.block_coverage)
            if cur_func_blocks:
                new_blocks.update(cur_func_blocks)
        for block_addr in new_blocks:
            cur_animation_css = get_animation_for_block(block_addr, i, num_total_frames)
            animation_css += cur_animation_css
    animation_css += "\n/* end animation CSS */"
    return animation_css


def escape(toescape):
    # handle extended unicode
    toescape = toescape.encode('ascii', 'xmlcharrefreplace')
    # still escape the basics
    if sys.version_info[0] == 3:
        return ''.join(escape_table.get(chr(i), chr(i)) for i in toescape)
    else:
        return ''.join(escape_table.get(i, i) for i in toescape)


def save_svg(bv, function, timeline, outputfile=None):
    sym = bv.get_symbol_at(function.start)
    if sym:
        offset = sym.name
    else:
        offset = "%x" % function.start
    path = Path(os.path.dirname(bv.file.filename))
    origname = os.path.basename(bv.file.filename)
    svg_path = path / f'binaryninja-{origname}-{offset}-animated.html'
    if outputfile is None:
        outputfile = str(svg_path)
    showOpcodes = False
    showAddresses = False

    content = render_html(function, offset, "Graph", "Assembly", showOpcodes, showAddresses, origname, timeline)
    with open(outputfile, 'w') as f:
        f.write(content)
        print(f'[+] Wrote {len(content)} bytes to "{outputfile}"')


def generate_css(function, timeline):
    default_css = '''
			@import url(https://fonts.googleapis.com/css?family=Source+Code+Pro);
			body {
				background-color: rgb(42, 42, 42);
								color: rgb(220, 220, 220);
								font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
			}
						a, a:visited  {
								color: rgb(200, 200, 200);
								font-weight: bold;
						}
			svg {
				background-color: rgb(42, 42, 42);
				display: block;
				margin: 0 auto;
			}
			.basicblock {
				stroke: rgb(224, 224, 224);
			}
			.edge {
				fill: none;
				stroke-width: 1px;
			}
			.back_edge {
				fill: none;
				stroke-width: 2px;
			}
			.UnconditionalBranch, .IndirectBranch {
				stroke: rgb(128, 198, 233);
				color: rgb(128, 198, 233);
			}
			.FalseBranch {
				stroke: rgb(222, 143, 151);
				color: rgb(222, 143, 151);
			}
			.TrueBranch {
				stroke: rgb(162, 217, 175);
				color: rgb(162, 217, 175);
			}
			.arrow {
				stroke-width: 1;
				fill: currentColor;
			}
			text {
								font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
				font-size: 9pt;
				fill: rgb(224, 224, 224);
			}
			.CodeSymbolToken {
				fill: rgb(128, 198, 223);
			}
			.DataSymbolToken {
				fill: rgb(142, 230, 237);
			}
			.TextToken, .InstructionToken, .BeginMemoryOperandToken, .EndMemoryOperandToken {
				fill: rgb(224, 224, 224);
			}
			.CodeRelativeAddressToken, .PossibleAddressToken, .IntegerToken, .AddressDisplayToken {
				fill: rgb(162, 217, 175);
			}
			.RegisterToken {
				fill: rgb(237, 223, 179);
			}
			.AnnotationToken {
				fill: rgb(218, 196, 209);
			}
			.IndirectImportToken, .ImportToken {
				fill: rgb(237, 189, 129);
			}
			.LocalVariableToken, .StackVariableToken {
				fill: rgb(193, 220, 199);
			}
			.OpcodeToken {
				fill: rgb(144, 144, 144);
			}
            .basicblock {
                fill: #4a4a4a;
            }
'''
    custom_css = get_custom_css(timeline, function)
    return f"{default_css}\n{custom_css}"


def render_html(function, offset, mode, form, showOpcodes, showAddresses, origname, timeline):
    """Build an HTML document containing an animated SVG showing coverage over time"""

    css = generate_css(function, timeline)
    svg = render_svg(function, offset, mode, form, showOpcodes, showAddresses, origname)

    output = f'''<html>
	<head>
		<style type="text/css">
{css}
		</style>
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.2/jquery.min.js"></script>
	</head>
{svg}
'''

    timestring = time.strftime("%c")
    func_description = f"showing {function.symbol.short_name}"
    output += f'<p>This CFG generated by <a href="https://binary.ninja/">Binary Ninja</a> from {origname} on {timestring} {func_description}.</p>'
    output += '</html>'
    return output


def render_svg(function, offset, mode, form, showOpcodes, showAddresses, origname):
    """Build SVG XML for the given function"""
    settings = DisassemblySettings()
    if showOpcodes:
        settings.set_option(DisassemblyOption.ShowOpcode, True)
    if showAddresses:
        settings.set_option(DisassemblyOption.ShowAddress, True)
    graph_type = FunctionGraphType.NormalFunctionGraph
    graph = function.create_graph(graph_type=graph_type, settings=settings)
    graph.layout_and_wait()

    heightconst = 15
    ratio = 0.48
    widthconst = heightconst * ratio

    function_name = function.name  # not guaranteed to be unique or pretty
    function_start = f'{function.start:x}'  # unique, not pretty
    demangled_function_name = function.symbol.short_name  # pretty, may not be unique
    
    output = '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{width}" height="{height}">
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
    output += f'''	<g id="func-{function_start}" class="functiongraph">
			<title>Graph of {demangled_function_name}</title>
	'''

    edges = ''
    for i, block in enumerate(graph):

        # Calculate basic block location and coordinates
        x = ((block.x) * widthconst)
        y = ((block.y) * heightconst)
        width = ((block.width) * widthconst)
        height = ((block.height) * heightconst)

        # Get basic block start address
        bb_start = f'{block.basic_block.start:x}'
        bb_id = f'bb-{bb_start}'

        # Render block
        output += '		<g>\n'
        output += f'			<title>Basic Block @ {bb_start}</title>\n'
        # We're going to override block colors with .basicblock default and CSS animation, so we omit fill color for each block
        output += f'			<rect id="{bb_id}"" class="basicblock" x="{x}" y="{y}" fill-opacity="0.4" height="{height+12}" width="{width+16}"/>\n'

        # Render instructions, unfortunately tspans don't allow copying/pasting more
        # than one line at a time, need SVG 1.2 textarea tags for that it looks like
        output += '			<text x="{x}" y="{y}">\n'.format(
            x=x, y=y + (i + 1) * heightconst)
        for i, line in enumerate(block.lines):
            output += '				<tspan id="instr-{address}" x="{x}" y="{y}">'.format(
                x=x + 6, y=y + 6 + (i + 0.7) * heightconst, address=hex(line.address)[:-1])
            for token in line.tokens:
                output += '<tspan class="{tokentype}">{text}</tspan>'.format(
                    text=escape(token.text), tokentype=InstructionTextTokenType(token.type).name)
            output += '</tspan>\n'
        output += '			</text>\n'
        output += '		</g>\n'

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
                edges += '		<polyline class="back_edge {type}" points="{points}" marker-end="url(#arrow-{type})"/>\n'.format(
                    type=BranchType(edge.type).name, points=points)
            else:
                edges += '		<polyline class="edge {type}" points="{points}" marker-end="url(#arrow-{type})"/>\n'.format(
                    type=BranchType(edge.type).name, points=points)

    output += ' ' + edges + '\n'
    output += '	</g>\n'
    output += '</svg>'

    return output


def animate_prompt(bv, function):
    # TODO: register a plugin hook
    # TODO: make sure this function signature matches the function plugin hook
    # TODO: prompt for a coverage file directory and coverage seed directory
    # TODO: make a coverage timeline, then pass into save_svg
    raise NotImplementedError
