#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>
#include "../opensnoop.h"

const int BPF_INSN_SIZE = sizeof(struct bpf_insn);
const int KEY_SIZE = sizeof(__u64);
const int VAL_T_SIZE = sizeof(struct val_t);
