from __future__ import annotations

import capstone

import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.disasm.jump
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import ljust_colored
from pwndbg.color import strip
from pwndbg.color.message import on
from pwndbg.disasm.instruction import InstructionCondition
from pwndbg.disasm.instruction import PwndbgInstruction

import pwndbg.gdblib.memory
import pwndbg.gdblib.strings
from pwndbg.color import light_green
import pwndbg.color.memory as M

capstone_branch_groups = {capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP}

c = ColorConfig(
    "disasm",
    [
        ColorParamSpec("branch", "bold", "color for disasm (branch/call instruction)"),
    ],
)


# Returns colorized instructions assembly and operands, and checkmark if branch is taken
#  Example: `✔ je     _IO_file_xsputn+341`. Inline symbol replacements made. No annotation or branch targets shown.
def one_instruction(ins: PwndbgInstruction) -> str:
    asm = ins.asm_string

    # Highlight the current line if enabled
    if pwndbg.gdblib.config.highlight_pc and ins.address == pwndbg.gdblib.regs.pc:
        asm = C.highlight(asm)

    is_call_or_jump = ins.groups_set & capstone_branch_groups

    # Style the instruction mnemonic if it's a call/jump instruction.
    if is_call_or_jump:
        asm = asm.replace(ins.mnemonic, c.branch(ins.mnemonic), 1)

    """
    for op in ins.operands[::-1]:
        addr = op.int
        if addr:
            length = pwndbg.gdblib.memory.strlen(addr)
            if length == 0:
                continue
            string = pwndbg.gdblib.strings.get(addr, maxlen=0, maxread=length+1)
            if string:
                asm = "%s %s" % (ljust_colored(asm, 36), light_green(gdb.Value(string)))
                break

    # If we know the conditional is taken, mark it as taken.
    if ins.condition == InstructionCondition.TRUE or ins.is_conditional_jump_taken:
        asm = on("✔ ") + asm
    else:
        asm = "  " + asm
    """

    return asm


MIN_SPACING = 5
WHITESPACE_LIMIT = 20


# To making the padding visually nicer, the following padding scheme is used for annotations:
# All instructions in a group will have the same amount of left-adjusting spaces, so they are aligned.
# A group is defined as a sequence of instructions surrounded by instructions that can change the instruction pointer.
def instructions_and_padding(instructions: list[PwndbgInstruction]) -> list[str]:
    result: list[str] = []

    cur_padding_len = None

    # Stores intermediate padding results so we can do a final pass to clean up edges and jagged parts
    # None if padding doesn't apply to the instruction
    paddings: list[int | None] = []

    # Used for padding. List of groups.
    # Each group is a list of index into paddings list
    groups: list[list[int]] = []

    current_group: list[int] = []

    for i, (ins, asm) in enumerate(zip(instructions, (one_instruction(i) for i in instructions))):
        if ins.can_change_instruction_pointer:
            sym = ins.target_string

            asm = f"{ljust_colored(asm, 36)} <{sym}>"

            paddings.append(None)
            if current_group:
                groups.append(current_group)
                current_group = []
        else:
            # Padding the string for a nicer output
            # This path calculates the padding for each instruction - even if there we don't have annotations for it.
            # This allows groups to have uniform padding, even if some of the instructions don't have annotations
            current_group.append(i)

            raw_len = len(strip(asm))

            if cur_padding_len is None:
                cur_padding_len = raw_len + MIN_SPACING
            elif cur_padding_len - raw_len < MIN_SPACING:
                # Annotations are getting too close to the disasm, push them to the right again
                cur_padding_len = raw_len + MIN_SPACING
            else:
                # This path allows the padding to be smaller again
                # If the instruction has too much whitespace, put the annotation more to the left
                # Make sure there is an instruction after this one, and it's not a branch. Otherwise, maintain current indentation.
                if (
                    i < len(instructions) - 1
                    and not instructions[i + 1].can_change_instruction_pointer
                    and cur_padding_len - raw_len > WHITESPACE_LIMIT
                ):
                    cur_padding_len = raw_len + MIN_SPACING

            # Give the padding to the instruction, so we can reuse it in the future
            if ins.annotation:
                if ins.annotation_padding is not None:
                    cur_padding_len = ins.annotation_padding
                else:
                    ins.annotation_padding = cur_padding_len

            paddings.append(cur_padding_len)

        result.append(asm)

    if current_group:
        groups.append(current_group)

    # Make instructions in each group aligned uniformly
    for group in groups:
        if len(group) == 0:
            continue

        # Find minimum spacing
        min_padding = max(paddings[index] for index in group)

        # Make all the paddings in this group have the same padding
        for index in group:
            paddings[index] = min_padding

    final_result = []

    # Final pass to apply final paddings to make alignment of blocks of instructions cleaner
    for i, (ins, asm, padding) in enumerate(zip(instructions, result, paddings)):
        if ins.annotation:
            asm = f"{ljust_colored(asm, padding)}{ins.annotation}"

        final_result.append(asm)

    return final_result


# this is a personal preference, but i dont like the annotations
# and the disassembly has changed to include everything in annotations, like symbols
# so just disabling annotations removes everything
# so i made a dirty change to use the previous instruction()

def legacy_instruction(ins):
    asm = ins.asm_string
    is_branch = set(ins.groups) & capstone_branch_groups

    operands = [o for o in ins.operands if o.symbol]
    if len(operands) == 1:
        symbol = operands[0].symbol
        symbol_addr = operands[0].before_value
    else:
        symbol = symbol_addr = None

    # Highlight the current line if enabled
    if pwndbg.gdblib.config.highlight_pc and ins.address == pwndbg.gdblib.regs.pc:
        asm = C.highlight(asm)

    # tl;dr is a branch?
    if ins.target not in (None, ins.address + ins.size):
        sym = pwndbg.gdblib.symbol.get(ins.target) or None
        target = M.get(ins.target)
        const = ins.target_const
        hextarget = hex(ins.target)
        hexlen = len(hextarget)

        # If it's a constant expression, color it directly in the asm.
        if const:
            asm = f"{ljust_colored(asm, 36)} <{target}>"
            asm = asm.replace(hex(ins.target), sym or target)

        # It's not a constant expression, but we've calculated the target
        # address by emulation or other means (for example showing ret instruction target)
        elif sym:
            asm = f"{ljust_colored(asm, 36)} <{target}; {sym}>"

        # We were able to calculate the target, but there is no symbol
        # name for it.
        else:
            asm += f"<{(target)}>"

    # not a branch
    elif symbol:
        if is_branch and not ins.target:
            asm = f"{asm} <{symbol}>"

            # XXX: not sure when this ever happens
            asm += "<-- file a pwndbg bug for this"
        else:
            inlined_sym = asm.replace(hex(symbol_addr), symbol)

            # display symbol as mem text if no inline replacement was made
            mem_text = symbol if inlined_sym == asm else None
            asm = f"{ljust_colored(inlined_sym, 36)} <{M.get(symbol_addr, mem_text)}>"

    # Style the instruction mnemonic if it's a branch instruction.
    if is_branch:
        asm = asm.replace(ins.mnemonic, c.branch(ins.mnemonic), 1)

    for op in ins.operands[::-1]:
        addr = None
        if op.cs_op.type != capstone.CS_OP_REG or ins.address == pwndbg.gdblib.regs.pc:
            addr = op.before_value
        if addr:
            length = pwndbg.gdblib.memory.strlen(addr)
            if length == 0:
                continue
            MAXLEN = 32
            string = pwndbg.gdblib.strings.get(addr, maxlen=length, maxread=length+1)
            if string:
                string = repr(string[:MAXLEN])
                if length > MAXLEN:
                    string += " ..."
                asm = "%s %s" % (ljust_colored(asm, 36), light_green(string))
                break

    # If we know the conditional is taken, mark it as taken.
    if ins.condition == InstructionCondition.TRUE or ins.is_conditional_jump_taken:
        asm = on("✔ ") + asm
    else:
        asm = "  " + asm

    return asm