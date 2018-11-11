#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>
#include <linux/version.h>

const int BPF_INSN_SIZE = sizeof(struct bpf_insn);
const int LINUX_VERSION_CODE_CONST = LINUX_VERSION_CODE;
const int LOG_BUF_SIZE_CONST = LOG_BUF_SIZE;
