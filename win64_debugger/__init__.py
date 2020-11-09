import click as _click
import traceback as _traceback

from win64_debugger.win64_debugger import Debugger


@_click.command()
@_click.option('-e', '--executable', help='Path to executable to be run and debugged.')
@_click.option('-p', '--pid', help='Existing process ID (pid) to attach debugger to.')
@_click.option('-sb', '--soft-breakpoint', help='Memory address to set a soft breakpoint at.')
def cli(executable, pid, soft_breakpoint):
    if (executable is None) and (pid is None):
        print("Either `--executable` or `--pid` must be specified to debug a process.")
        return

    debugger = Debugger()

    if executable is not None:
        debugger.load(executable)
    elif pid is not None:
        debugger.attach(int(pid))
    
    if soft_breakpoint is not None:
        debugger.set_soft_breakpoint(soft_breakpoint)

    try:
        debugger.run()
        debugger.detach()
    except Exception as e:
        print(_traceback.format_exc())
