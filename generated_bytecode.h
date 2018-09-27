// GENERATED FILE: See opensnoop.py.
#include <bcc/libbpf.h>
#include <stdlib.h>

#define MAX_NUM_TRACE_ENTRY_INSTRUCTIONS 35
#define NUM_TRACE_ENTRY_INSTRUCTIONS 28
#define NUM_TRACE_ENTRY_TID_INSTRUCTIONS 32
#define NUM_TRACE_ENTRY_PID_INSTRUCTIONS 35
#define NUM_TRACE_RETURN_INSTRUCTIONS 82

void generate_trace_entry(struct bpf_insn instructions[], int fd3) {
  instructions[0] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_7,
      .src_reg = BPF_REG_1,
      .off     = 104,
      .imm     = 0,
  };
  instructions[1] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[2] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -8,
      .imm     = 0,
  };
  instructions[3] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -16,
      .imm     = 0,
  };
  instructions[4] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -24,
      .imm     = 0,
  };
  instructions[5] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -32,
      .imm     = 0,
  };
  instructions[6] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 14,
  };
  instructions[7] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_6,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[8] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -40,
      .imm     = 0,
  };
  instructions[9] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[10] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -24,
  };
  instructions[11] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[12] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[13] = (struct bpf_insn) {
      .code    = 0x67,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[14] = (struct bpf_insn) {
      .code    = 0x77,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[15] = (struct bpf_insn) {
      .code    = 0x55,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 10,
      .imm     = 0,
  };
  instructions[16] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_7,
      .off     = -8,
      .imm     = 0,
  };
  instructions[17] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -32,
      .imm     = 0,
  };
  instructions[18] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = fd3,
  };
  instructions[19] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[20] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[21] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -40,
  };
  instructions[22] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[23] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -32,
  };
  instructions[24] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[25] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 2,
  };
  instructions[26] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[27] = (struct bpf_insn) {
      .code    = 0x95,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
}

void generate_trace_entry_tid(struct bpf_insn instructions[], int tid, int fd3) {
  instructions[0] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_7,
      .src_reg = BPF_REG_1,
      .off     = 104,
      .imm     = 0,
  };
  instructions[1] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[2] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -8,
      .imm     = 0,
  };
  instructions[3] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -16,
      .imm     = 0,
  };
  instructions[4] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -24,
      .imm     = 0,
  };
  instructions[5] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -32,
      .imm     = 0,
  };
  instructions[6] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 14,
  };
  instructions[7] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_6,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[8] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -40,
      .imm     = 0,
  };
  instructions[9] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_6,
      .off     = 0,
      .imm     = 0,
  };
  instructions[10] = (struct bpf_insn) {
      .code    = 0x67,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[11] = (struct bpf_insn) {
      .code    = 0x77,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[12] = (struct bpf_insn) {
      .code    = 0x55,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 17,
      .imm     = tid,
  };
  instructions[13] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[14] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -24,
  };
  instructions[15] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[16] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[17] = (struct bpf_insn) {
      .code    = 0x67,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[18] = (struct bpf_insn) {
      .code    = 0x77,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[19] = (struct bpf_insn) {
      .code    = 0x55,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 10,
      .imm     = 0,
  };
  instructions[20] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_7,
      .off     = -8,
      .imm     = 0,
  };
  instructions[21] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -32,
      .imm     = 0,
  };
  instructions[22] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = fd3,
  };
  instructions[23] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[24] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[25] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -40,
  };
  instructions[26] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[27] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -32,
  };
  instructions[28] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[29] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 2,
  };
  instructions[30] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[31] = (struct bpf_insn) {
      .code    = 0x95,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
}

void generate_trace_entry_pid(struct bpf_insn instructions[], int pid, int fd3) {
  instructions[0] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_7,
      .src_reg = BPF_REG_1,
      .off     = 104,
      .imm     = 0,
  };
  instructions[1] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[2] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -8,
      .imm     = 0,
  };
  instructions[3] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -16,
      .imm     = 0,
  };
  instructions[4] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -24,
      .imm     = 0,
  };
  instructions[5] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -32,
      .imm     = 0,
  };
  instructions[6] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 14,
  };
  instructions[7] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_6,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[8] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -40,
      .imm     = 0,
  };
  instructions[9] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[10] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -1,
  };
  instructions[11] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_6,
      .off     = 0,
      .imm     = 0,
  };
  instructions[12] = (struct bpf_insn) {
      .code    = 0x5f,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = 0,
  };
  instructions[13] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[14] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = pid,
  };
  instructions[15] = (struct bpf_insn) {
      .code    = 0x5d,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_1,
      .off     = 17,
      .imm     = 0,
  };
  instructions[16] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[17] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -24,
  };
  instructions[18] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[19] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[20] = (struct bpf_insn) {
      .code    = 0x67,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[21] = (struct bpf_insn) {
      .code    = 0x77,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 32,
  };
  instructions[22] = (struct bpf_insn) {
      .code    = 0x55,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 10,
      .imm     = 0,
  };
  instructions[23] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_7,
      .off     = -8,
      .imm     = 0,
  };
  instructions[24] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_6,
      .off     = -32,
      .imm     = 0,
  };
  instructions[25] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = fd3,
  };
  instructions[26] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[27] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[28] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -40,
  };
  instructions[29] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[30] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -32,
  };
  instructions[31] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[32] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 2,
  };
  instructions[33] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[34] = (struct bpf_insn) {
      .code    = 0x95,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
}

void generate_trace_return(struct bpf_insn instructions[], int fd3, int fd4) {
  instructions[0] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_6,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = 0,
  };
  instructions[1] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 14,
  };
  instructions[2] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_0,
      .off     = -8,
      .imm     = 0,
  };
  instructions[3] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[4] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -16,
      .imm     = 0,
  };
  instructions[5] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -24,
      .imm     = 0,
  };
  instructions[6] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -32,
      .imm     = 0,
  };
  instructions[7] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -40,
      .imm     = 0,
  };
  instructions[8] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -48,
      .imm     = 0,
  };
  instructions[9] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -56,
      .imm     = 0,
  };
  instructions[10] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -64,
      .imm     = 0,
  };
  instructions[11] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -72,
      .imm     = 0,
  };
  instructions[12] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -80,
      .imm     = 0,
  };
  instructions[13] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -88,
      .imm     = 0,
  };
  instructions[14] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -96,
      .imm     = 0,
  };
  instructions[15] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -104,
      .imm     = 0,
  };
  instructions[16] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -112,
      .imm     = 0,
  };
  instructions[17] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -120,
      .imm     = 0,
  };
  instructions[18] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -128,
      .imm     = 0,
  };
  instructions[19] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -136,
      .imm     = 0,
  };
  instructions[20] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -144,
      .imm     = 0,
  };
  instructions[21] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -152,
      .imm     = 0,
  };
  instructions[22] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -160,
      .imm     = 0,
  };
  instructions[23] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -168,
      .imm     = 0,
  };
  instructions[24] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -176,
      .imm     = 0,
  };
  instructions[25] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -184,
      .imm     = 0,
  };
  instructions[26] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -192,
      .imm     = 0,
  };
  instructions[27] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -200,
      .imm     = 0,
  };
  instructions[28] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -208,
      .imm     = 0,
  };
  instructions[29] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -216,
      .imm     = 0,
  };
  instructions[30] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -224,
      .imm     = 0,
  };
  instructions[31] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -232,
      .imm     = 0,
  };
  instructions[32] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -240,
      .imm     = 0,
  };
  instructions[33] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -248,
      .imm     = 0,
  };
  instructions[34] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -256,
      .imm     = 0,
  };
  instructions[35] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -264,
      .imm     = 0,
  };
  instructions[36] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -272,
      .imm     = 0,
  };
  instructions[37] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -280,
      .imm     = 0,
  };
  instructions[38] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -288,
      .imm     = 0,
  };
  instructions[39] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -296,
      .imm     = 0,
  };
  instructions[40] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -304,
      .imm     = 0,
  };
  instructions[41] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 5,
  };
  instructions[42] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_7,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[43] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = fd3,
  };
  instructions[44] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[45] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[46] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -8,
  };
  instructions[47] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 1,
  };
  instructions[48] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_8,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[49] = (struct bpf_insn) {
      .code    = 0x15,
      .dst_reg = BPF_REG_8,
      .src_reg = BPF_REG_0,
      .off     = 30,
      .imm     = 0,
  };
  instructions[50] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_8,
      .off     = 0,
      .imm     = 0,
  };
  instructions[51] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 8,
  };
  instructions[52] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[53] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -284,
  };
  instructions[54] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 16,
  };
  instructions[55] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 4,
  };
  instructions[56] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_8,
      .off     = 24,
      .imm     = 0,
  };
  instructions[57] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[58] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -268,
  };
  instructions[59] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 255,
  };
  instructions[60] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 4,
  };
  instructions[61] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_8,
      .off     = 0,
      .imm     = 0,
  };
  instructions[62] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_7,
      .off     = -296,
      .imm     = 0,
  };
  instructions[63] = (struct bpf_insn) {
      .code    = 0x7b,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -304,
      .imm     = 0,
  };
  instructions[64] = (struct bpf_insn) {
      .code    = 0x79,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_6,
      .off     = 80,
      .imm     = 0,
  };
  instructions[65] = (struct bpf_insn) {
      .code    = 0x63,
      .dst_reg = BPF_REG_10,
      .src_reg = BPF_REG_1,
      .off     = -288,
      .imm     = 0,
  };
  instructions[66] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = fd4,
  };
  instructions[67] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[68] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[69] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_4,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -304,
  };
  instructions[70] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_6,
      .off     = 0,
      .imm     = 0,
  };
  instructions[71] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_3,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -1,
  };
  instructions[72] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[73] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_5,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 296,
  };
  instructions[74] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 25,
  };
  instructions[75] = (struct bpf_insn) {
      .code    = 0x18,
      .dst_reg = BPF_REG_1,
      .src_reg = BPF_REG_1,
      .off     = 0,
      .imm     = fd3,
  };
  instructions[76] = (struct bpf_insn) {
      .code    = 0x0,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[77] = (struct bpf_insn) {
      .code    = 0xbf,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_10,
      .off     = 0,
      .imm     = 0,
  };
  instructions[78] = (struct bpf_insn) {
      .code    = 0x7,
      .dst_reg = BPF_REG_2,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = -8,
  };
  instructions[79] = (struct bpf_insn) {
      .code    = 0x85,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 3,
  };
  instructions[80] = (struct bpf_insn) {
      .code    = 0xb7,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
  instructions[81] = (struct bpf_insn) {
      .code    = 0x95,
      .dst_reg = BPF_REG_0,
      .src_reg = BPF_REG_0,
      .off     = 0,
      .imm     = 0,
  };
}

