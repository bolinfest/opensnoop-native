from binascii import hexlify
import struct

# This list comes from `enum bpf_func_id`:
# https://elixir.bootlin.com/linux/v4.7/source/include/uapi/linux/bpf.h#L146
_bpf_func_id = [
    "bpf_unspec",
    "bpf_map_lookup_elem",
    "bpf_map_update_elem",
    "bpf_map_delete_elem",
    "bpf_probe_read",
    "bpf_ktime_get_ns",
    "bpf_trace_printk",
    "bpf_get_prandom_u32",
    "bpf_get_smp_processor_id",
    "bpf_skb_store_bytes",
    "bpf_l3_csum_replace",
    "bpf_l4_csum_replace",
    "bpf_tail_call",
    "bpf_clone_redirect",
    "bpf_get_current_pid_tgid",
    "bpf_get_current_uid_gid",
    "bpf_get_current_comm",
    "bpf_get_cgroup_classid",
    "bpf_skb_vlan_push",
    "bpf_skb_vlan_pop",
    "bpf_skb_get_tunnel_key",
    "bpf_skb_set_tunnel_key",
    "bpf_perf_event_read",
    "bpf_redirect",
    "bpf_get_route_realm",
    "bpf_perf_event_output",
    "bpf_skb_load_bytes",
    "bpf_get_stackid",
    "bpf_csum_diff",
    "bpf_skb_get_tunnel_opt",
    "bpf_skb_set_tunnel_opt",
]


def get_list_of_instructions(bytecode):
    for index, b_offset in enumerate(xrange(0, len(bytecode), 8)):
        instruction = bytecode[b_offset : b_offset + 8]
        yield index, instruction


def print_list_of_instructions(bytecode):
    iterator = get_list_of_instructions(bytecode)
    next_instr = [None]

    def decode_instruction(instruction):
        opcode, dst_reg, src_reg, offset, imm = parse_instruction(instruction)
        if opcode == 0x00:
            return "error: should have been handled by previous instruction"
        instruction_class = 0x07 & opcode

        if instruction_class == 0x07:
            # ALU instruction
            if 0x08 & opcode:
                src_operand = "r%d" % src_reg
            else:
                src_operand = "%d" % imm

            operation = (0xF0 & opcode) >> 4
            op_suffix = ""
            if operation == 0x0:
                op = "+="
            elif operation == 0x1:
                op = "-="
            elif operation == 0x2:
                op = "*="
            elif operation == 0x3:
                op = "/="
            elif operation == 0x4:
                op = "|="
            elif operation == 0x5:
                op = "&="
            elif operation == 0x6:
                op = "<<="
            elif operation == 0x7:
                op = ">>="
                op_suffix = " (logical)"
            elif operation == 0x8:
                op = "= -"
            elif operation == 0x9:
                op = "%="
            elif operation == 0xa:
                op = "^="
            elif operation == 0xb:
                op = "="
            elif operation == 0xc:
                op = ">>="
                op_suffix = " (arithmetic)"
            else:
                op = "op?"
            return "r%d %s %s%s" % (dst_reg, op, src_operand, op_suffix)
        elif opcode == 0x85:
            return "call %s()" % _bpf_func_id[imm]
        elif opcode == 0x95:
            return "exit"

        elif opcode == 0x55:
            return "PC += %d if r%d != %d" % (offset, dst_reg, imm)

        elif opcode == 0x79:
            return "*(u64 *) r%d = (r%d + %d)" % (dst_reg, src_reg, offset)
        elif opcode == 0x73:
            return "*(u8 *) (r%d + %d) = r%d" % (dst_reg, offset, src_reg)
        elif opcode == 0x7b:
            return "*(u64 *) (r%d + %d) = r%d" % (dst_reg, offset, src_reg)

        elif opcode == 0x18:
            _, next_instruction = iterator.next()
            next_instr[0] = next_instruction
            _, _, _, _, imm_next = parse_instruction(next_instruction)
            upper_bits = format_imm_bytes(imm_next)
            lower_bits = format_imm_bytes(imm)
            return "r%d = 0x%s%s" % (dst_reg, upper_bits, lower_bits)
        else:
            return "!!!"

    for index, instruction in iterator:
        next_instr[0] = None
        comment = decode_instruction(instruction)
        print("%2d %s # %s" % (index, hexlify(instruction), comment))
        if next_instr[0]:
            print("%2d %s" % (index + 1, hexlify(next_instr[0])))


def format_imm_bytes(imm):
    s = hexlify(struct.pack("i", imm))
    s = s.rjust(8, " ")
    return s[6:8] + s[4:6] + s[2:4] + s[0:2]


bpf_insn_template = """\
  ((struct bpf_insn) {
      .code    = 0x%x,
      .dst_reg = BPF_REG_%d,
      .src_reg = BPF_REG_%d,
      .off     = %d,
      .imm     = %d,
  }),
"""


def parse_instruction(instruction):
    # u8
    opcode = struct.unpack("B", instruction[0])[0]

    src_and_dst = struct.unpack("B", instruction[1])[0]
    # The low-order nibble is dst.
    dst_reg = src_and_dst & 0x0F
    # The high-order nibble is src.
    src_reg = (src_and_dst & 0xF0) >> 4

    # s16
    offset = struct.unpack("h", instruction[2:4])[0]
    # s32
    imm = struct.unpack("i", instruction[4:8])[0]
    return (opcode, dst_reg, src_reg, offset, imm)


def print_bpf_insns(bytecode, array_name, f):
    """Prints the eBPF bytecode as the equivalent bpf_insn[] in C."""
    f.write(
        """\
// GENERATED FILE: See opensnoop.py.
#include <bcc/libbpf.h>

struct bpf_insn %s[] = {
"""
        % array_name
    )
    for b_offset in xrange(0, len(bytecode), 8):
        instruction = bytecode[b_offset : b_offset + 8]
        opcode, dst_reg, src_reg, offset, imm = parse_instruction(instruction)
        f.write(bpf_insn_template % (opcode, dst_reg, src_reg, offset, imm))
    f.write("};\n")


# Note imm is normally an integer, though
# generate_c_function() has a special case
# where it is a variable name.
insn_assign_template = """\
  instructions[%d] = (struct bpf_insn) {
      .code    = 0x%x,
      .dst_reg = BPF_REG_%d,
      .src_reg = BPF_REG_%d,
      .off     = %d,
      .imm     = %s,
  };
"""

c_function_template = """\
void %s(struct bpf_insn instructions[]%s) {
%s}

"""


def generate_c_function(fn_name, bytecode, placeholder=None):
    assigns = []
    fds = set()
    for index, instruction in get_list_of_instructions(bytecode):
        opcode, dst_reg, src_reg, offset, imm = parse_instruction(instruction)
        # I haven't found proper documentation for ld_pseudo, but I am basing
        # this off of
        # https://github.com/iovisor/bcc/blob/6ce918bd7030241f0598ee6b1107940bf8480085/src/cc/bcc_debug.cc#L53-L58
        if opcode == 0x18 and src_reg == 1:
            fd = imm
            fds.add(fd)
            imm = "fd%d" % fd
        elif placeholder and imm == placeholder["imm"]:
            imm = placeholder["param_name"]
        assigns.append(
            insn_assign_template % (index, opcode, dst_reg, src_reg, offset, imm)
        )

    sig = ""
    if placeholder:
        sig += ", %s %s" % (placeholder["param_type"], placeholder["param_name"])
    if fds:
        sorted_fds = list(fds)
        sorted_fds.sort()
        params = [", int fd%d" % fd for fd in sorted_fds]
        sig += "".join(params)
    code = c_function_template % (fn_name, sig, "".join(assigns))
    return code
