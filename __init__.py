from binaryninja import PluginCommand

from .phantasm.plugin import make_visualization

PluginCommand.register_for_function(
    "Phantasm\\Animate Current Function",
    "Generate visualization",
    make_visualization
)
