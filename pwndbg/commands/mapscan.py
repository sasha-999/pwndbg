"""
Command to scan the memory regions for PIE, libc, heap and more
"""
import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.vmmap
from pwndbg.commands import CommandCategory

import os
import elftools.common.exceptions
import pwndbg.color as C
from pwndbg.wrappers.readelf import check_if_symbol_exists
from pwndbg.glibc import get_libc_filename_from_info_sharedlibrary

colors = {
"PIE"           :   lambda x: C.memory.c.data(x),
"interpreter"   :   lambda x: C.red(x),
"glibc"         :   lambda x: C.bold(C.light_green(x)),
"shared library":   lambda x: C.green(x),
"stack"         :   lambda x: C.memory.c.stack(x),
"heap"          :   lambda x: C.memory.c.heap(x),
}
pad_name_len = max([len(x) for x in colors.keys()]) + 1

def print_line(name, address, path=None):
    width = 2 + 2*pwndbg.gdblib.arch.ptrsize
    pad_name = name.ljust(pad_name_len, ' ')
    if path:
        line = "%s: %#{}x (%s)".format(width) % (pad_name, address, path)
    else:
        line = "%s: %#{}x".format(width)      % (pad_name, address)
    color = colors[name]
    print(color(line))

def is_standard_libc(exe):
    # pretty decent heuristic, works for most libc binaries
    # fails for a few that don't contain a version string
    if check_if_symbol_exists(exe, "gnu_get_libc_version"):
        return True
    # fallback on a case that should work most of the time
    # by using name matching
    libc = get_libc_filename_from_info_sharedlibrary()
    if libc is None:
        return False
    return os.path.samefile(exe, libc)

@pwndbg.commands.ArgparsedCommand(
    "Scan memory pages for shared libraries, interpreter, heap, stack, PIE",
    aliases=["mscan"], category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def mapscan():
    pages = pwndbg.gdblib.vmmap.get()
    auxv = pwndbg.auxv.get()
    found = ['']

    exe = pwndbg.commands.pie.get_exe_name()
    for page in pages:
        if page.objfile in found:
            continue
        found.append(page.objfile)

        if os.path.isfile(page.objfile):
            # base of current executable (PIE)
            if page.objfile.endswith(exe):
                gdb.set_convenience_variable("pie", page.start)
                print_line("PIE", page.start, path=page.objfile)
            # interpreter
            elif page.start == auxv.get("AT_BASE"):
                gdb.set_convenience_variable("interp", page.start)
                print_line("interpreter", page.start, path=page.objfile)
            else:
                # TODO: replace the get_elf_info and readelf with ELFFile

                # check that it's a shared library
                try:
                    elf = pwndbg.gdblib.elf.get_elf_info(page.objfile)
                except elftools.common.exceptions.ELFError:
                    continue
                # shared libraries must be PIC/PIE
                if not elf.is_pic:
                    continue
                # check for standard glibc symbol
                # (not a perfect heuristic)
                if is_standard_libc(page.objfile):
                    # shared library has the symbol, must be glibc
                    gdb.set_convenience_variable("libc", page.start)
                    print_line("glibc", page.start, path=page.objfile)
                else:
                    # otherwise, it's just another shared library
                    print_line("shared library", page.start, path=page.objfile)

        else:
            # stack
            if page.objfile == "[stack]":
                gdb.set_convenience_variable("stack", page.start)
                print_line("stack", page.start)
            # heap
            elif page.objfile == "[heap]":
                gdb.set_convenience_variable("heap", page.start)
                print_line("heap", page.start)
