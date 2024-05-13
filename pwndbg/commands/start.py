"""
Launches the target process after setting a breakpoint at a convenient
entry point.
"""

from __future__ import annotations

import argparse
from argparse import RawTextHelpFormatter
from shlex import quote

import gdb

import pwndbg.commands
import pwndbg.gdblib.elf
import pwndbg.gdblib.events
import pwndbg.gdblib.symbol
from pwndbg.commands import CommandCategory

import pwndbg.lib.abi
import pwndbg.gdblib.regs
import pwndbg.gdblib.memory
import pwndbg.gdblib.proc
from pwndbg.color import message

break_on_first_instruction = False


@pwndbg.gdblib.events.start
def on_start() -> None:
    global break_on_first_instruction
    if break_on_first_instruction:
        spec = "*%#x" % (int(pwndbg.gdblib.elf.entry()))
        gdb.Breakpoint(spec, temporary=True)
        break_on_first_instruction = False


# Starting from 3rd paragraph, the description is
# taken from the GDB's `starti` command description
parser = argparse.ArgumentParser(
    formatter_class=pwndbg.commands.RawTextArgsFormatter,
    description="""
Start the debugged program stopping at the first convenient location
from this list: main, _main, start, _start, init or _init.
You may specify arguments to give it.

Args may include "*", or "[...]"; they are expanded using the
shell that will start the program (specified by the "$SHELL" environment
variable).  Input and output redirection with ">", "<", or ">>"
are also allowed.

With no arguments, uses arguments last specified (with "run" or
"set args").  To cancel previous arguments and run with no arguments,
use "set args" without arguments.

To start the inferior without using a shell, use "set startup-with-shell off".
""",
)

parser.add_argument(
    "args", nargs="*", type=str, default=None, help="The arguments to run the binary with."
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["main", "init"], category=CommandCategory.START)
def start(args=None) -> None:
    if args is None:
        args = []
    run = "run " + " ".join(args)

    symbols = ["main", "_main", "start", "_start", "init", "_init"]

    for symbol in symbols:
        address = pwndbg.gdblib.symbol.address(symbol)

        if not address:
            continue

        gdb.Breakpoint(symbol, temporary=True)
        gdb.execute(run, from_tty=False, to_string=True)
        return

    # Try a breakpoint at the binary entry
    entry(args)


# Starting from 3rd paragraph, the description is
# taken from the GDB's `starti` command description
parser = argparse.ArgumentParser(
    formatter_class=pwndbg.commands.RawTextArgsFormatter,
    description="""
Start the debugged program stopping at its entrypoint address.

Note that the entrypoint may not be the first instruction executed
by the program. If you want to stop on the first executed instruction,
use the GDB's `starti` command.

Args may include "*", or "[...]"; they are expanded using the
shell that will start the program (specified by the "$SHELL" environment
variable).  Input and output redirection with ">", "<", or ">>"
are also allowed.

With no arguments, uses arguments last specified (with "run" or
"set args").  To cancel previous arguments and run with no arguments,
use "set args" without arguments.

To start the inferior without using a shell, use "set startup-with-shell off".
""",
)
parser.add_argument(
    "args", nargs="*", type=str, default=[], help="The arguments to run the binary with."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.START)
@pwndbg.commands.OnlyWithFile
def entry(args=[]) -> None:
    global break_on_first_instruction
    break_on_first_instruction = True
    #run = "run " + " ".join(map(quote, args))
    run = "run " + args[0]
    gdb.execute(run, from_tty=False)


@pwndbg.commands.ArgparsedCommand(
    "Alias for 'tbreak __libc_start_main; run'.", category=CommandCategory.START
)
@pwndbg.commands.OnlyWithFile
def sstart() -> None:
    gdb.Breakpoint("__libc_start_main", temporary=True)
    gdb.execute("run")


def run_until(addr=None, name=None):
    if addr:
        name = "*%#x" % addr
    gdb.Breakpoint(name, temporary=True)
    gdb.execute("continue", from_tty=False)

parser = argparse.ArgumentParser(
    formatter_class=pwndbg.commands.RawTextArgsFormatter,
    description="""
Break on the main function in a linux C binary.
The 2 approaches used are:
* Breaking on the 'main' symbol if it exists.
* Breaking on '__libc_start_main' and finding main from the first argument.

If the program isn't running, it will first break on entry.
Otherwise it continues from the current point.
""",
)
parser.add_argument("args", nargs="*", type=str, default=[], help="The arguments to run the binary with.")
@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.START)
@pwndbg.commands.OnlyWithFile
def bmain(args=[]):
    if not pwndbg.gdblib.proc.alive:
        # start on entry point
        entry(args)
        on_entry = True
    else:
        on_entry = False

    # check if main is a symbol
    main = pwndbg.gdblib.symbol.address("main")
    if main:
        gdb.set_convenience_variable("main", main)
        run_until(name="main")
        return

    # attempt to break on __libc_start_main
    # first argument passed to __libc_start_main is main
    start_main = pwndbg.gdblib.symbol.address("__libc_start_main")
    if start_main:
        run_until(addr=start_main)
    else:
        # __libc_start_main doesn't exist
        print(message.warn("__libc_start_main wasn't found!"))
        if on_entry:
            print(message.warn("Currently at Entry Point"))
        return

    # get calling convention
    abi = pwndbg.lib.abi.ABI.default()
    if abi is None:
        # ABI wasn't found
        # unlikely to happen
        print(message.warn("Process' ABI wasn't found!"))
        print(message.warn("Currently at __libc_start_main"))
        print(message.warn("main will be the first argument!"))
        return
    # get first argument of __libc_start_main()
    regs = abi.register_arguments
    if len(regs) > 0:
        # first argument will be in the first register
        first = abi.register_arguments[0]
        main = getattr(pwndbg.gdblib.regs, first)
    else:
        # ABI doesn't use registers for arguments
        # must use stack for all arguments (likely i386)
        main = pwndbg.gdblib.memory.u(pwndbg.gdblib.regs.sp + pwndbg.gdblib.arch.ptrsize)


    if main:
        gdb.set_convenience_variable("main", main)
        run_until(addr=main)
    else:
        print(message.error("Unexpected error, main not found!"))
        print(message.warn("Currently at __libc_start_main"))
