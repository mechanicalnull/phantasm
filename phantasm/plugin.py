import os
from pathlib import Path
from time import time

from binaryninja import log_info, log_error, log_debug
from binaryninja import DirectoryNameField, ChoiceField, SaveFileNameField, get_form_input, show_html_report

from bncov import CoverageDB
from .timeline import CoverageTimeline
from .visualize import generate_html


def prompt_for_settings(bv, func):
    form_fields = []
    form_fields.append(f'Function to Graph: {func.symbol.short_name}')

    corpus_dir_choice = DirectoryNameField("Corpus Directory (inputs)")
    form_fields.append(corpus_dir_choice)

    coverage_dir_choice = DirectoryNameField("Coverage Directory (*.cov)")
    form_fields.append(coverage_dir_choice)

    show_opcodes_field = ChoiceField("Show Opcodes", ["No", "Yes"])
    form_fields.append(show_opcodes_field)

    show_addresses_field = ChoiceField("Show Addresses", ["No", "Yes"])
    form_fields.append(show_addresses_field)

    orig_name = os.path.basename(bv.file.original_filename)
    default_outputfile = f'phantasm-{orig_name}-{func.symbol.short_name}.html'
    output_file_choice = SaveFileNameField("Output file", 'HTML files (*.html)', default_outputfile)
    form_fields.append(output_file_choice)

    if not get_form_input(form_fields, "Phantasm Generation") or output_file_choice.result is None:
        return None

    output_file = output_file_choice.result
    if output_file == '':
        output_file = default_outputfile
        log_info(f'Phantasm: No output filename supplied, using default {output_file}')

    settings = (
        corpus_dir_choice.result,
        coverage_dir_choice.result,
        show_opcodes_field.result,
        show_addresses_field.result,
        output_file,
    )
    return settings


def make_visualization(bv, func):
    """For interactive use, promps user for settings, then renders viz to file"""

    settings = prompt_for_settings(bv, func)
    if settings is None:
        return
    corpus_dir, coverage_dir, show_opcodes, show_addresses, output_file = settings

    if not os.path.exists(corpus_dir):
        log_error(f'Corpus directory "{corpus_dir}" not found')
        return
    if not os.path.exists(coverage_dir):
        log_error(f'Coverage directory "{coverage_dir}" not found')
        return

    log_info(f"Phantasm: Graphing coverage for {func.symbol.short_name}")
    log_info(f"  Corpus dir: {corpus_dir}")
    log_info(f"  Coverage dir: {coverage_dir}")

    html_content = generate_coverage_over_time(bv, func, corpus_dir, coverage_dir, show_opcodes, show_addresses)
    if len(html_content) == 0:
        return ''

    output_path = os.path.abspath(output_file)
    with open(output_file, 'w') as f:
        f.write(html_content)
        log_info(f'Phantasm: Wrote visualization to "{output_path}"')

    return output_path


def graph_coverage(bv, func, corpus_dir, coverage_dir, output_file=None, show_opcodes=True, show_addresses=True):
    """Renders visualization to a file; for headless use"""
    if isinstance(func, str):
        func = next(f for f in bv.functions if f.name == func)

    if output_file is None:
        auto_name = f'phantasm-{os.path.basename(bv.file.original_filename)}-{func.name}.html'
        output_file = os.path.join(os.getcwd(), auto_name)

    html_content = generate_coverage_over_time(bv, func, corpus_dir, coverage_dir, show_opcodes, show_addresses)
    if len(html_content) == 0:
        return ''

    with open(output_file, 'w') as f:
        f.write(html_content)
    print(f'Wrote {os.path.getsize(output_file)} bytes to "{output_file}"')

    return output_file


def generate_coverage_over_time(bv, func, corpus_dir, coverage_dir, show_opcodes, show_addresses):
    """Calculate coverage timeline, then build the html visualization"""

    start_time = time()
    covdb = CoverageDB(bv)
    covdb.add_directory(coverage_dir)
    duration = time() - start_time
    log_debug(f'Phantasm: Coverage loaded in {duration:.2f} seconds')

    def map_coverage_to_corpus(coverage_path: Path) -> Path:
        coverage_name = coverage_path.name
        if coverage_name.endswith('.cov'):
            input_name = coverage_name[:-4]
        else:
            input_name = coverage_name
        corpus_dir_path = Path(corpus_dir)
        return corpus_dir_path.joinpath(input_name)

    start_time = time()
    cov_timeline = CoverageTimeline(bv, [covdb,])
    cov_timeline.get_seed_from_coverage_file = map_coverage_to_corpus
    cov_timeline.process_timeline()

    unique_timestamps = len(cov_timeline.sorted_timestamps)
    if unique_timestamps <= 1:
        log_error(f'[!] Phantasm: Only detected {unique_timestamps} unique timestamps,' +
                   ' which means coverage over time is not meaningful\n')
        log_error('    If you copied the corpus directory around, ensure you ' +
                  'preserve timestamps with `cp -a` or equivalent')
        return ''

    cov_timeline.print_total_coverage_delta(func)
    duration = time() - start_time
    log_debug(f'Phantasm: Timeline calculated in {duration:.2f} seconds')

    start_time = time()
    html_content = generate_html(bv, func, cov_timeline, show_opcodes, show_addresses)
    duration = time() - start_time
    log_debug(f'Phantasm: HTML generated in {duration:.2f} seconds')

    return html_content
