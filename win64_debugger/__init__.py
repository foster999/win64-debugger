import click as _click
import functools as _functools
import traceback as _traceback

from win64_debugger.win64_debugger import Debugger

@_click.group()
def cli():
    pass


def _breakpoint_options(f):
    """Decorator to add breakpoint options.
    """
    options = [
        _click.option('-sb', '--soft-breakpoint', help='Memory address to set a soft breakpoint at.'),
        _click.option('-hb', '--hardware-breakpoint', help='Memory address to set a hardware breakpoint at.'),
        _click.option('-mb', '--memory-breakpoint', help='Memory address to set a memory breakpoint at.')
    ]
    return _functools.reduce(lambda x, opt: opt(x), options, f)

def _handle_breakpoint_options(debugger, **kwargs):
    print(**kwargs)
    if kwargs.get("soft_breakpoint"):
            debugger.set_soft_breakpoint(kwargs.get("soft_breakpoint"))
    if kwargs.get("hardware_breakpoint"):
            debugger.set_hardware_breakpoint(kwargs.get("hardware_breakpoint"))
    if kwargs.get("memory_breakpoint"):
            debugger.set_memory_breakpoint(kwargs.get("memory_breakpoint"))        


@cli.command()
@_click.argument('dll')
@_click.argument('function')
def resolve(dll, function):
    """resolve the memory address of a function.

    dll is the name of module containing the function.
    function is the name of the function to resolve the address of.
    """
    print(Debugger.resolve_function_address(dll, function))


@cli.command()
@_click.argument('pid')
@_breakpoint_options
def debug(pid, **kwargs):
    """debug an active process.

    pid is the ID of the process to debug.
    """
    with Debugger() as debugger:
        debugger.attach(int(pid))
        _handle_breakpoint_options(debugger, **kwargs)


@cli.command()
@_click.argument("command", nargs=-1)
@_breakpoint_options
def run(command, **kwargs):
    """run an excecutable and debug the process.

    command is the command and arguments to run and debug.
    """
    with Debugger() as debugger:
        debugger.load(command)
        _handle_breakpoint_options(debugger, **kwargs)
