import os
from bcc import (
    BPF,
    DEBUG_LLVM_IR,
    DEBUG_PREPROCESSOR,
    DEBUG_SOURCE,
    DEBUG_BPF_REGISTER_STATE,
)
from debug import generate_c_function

# define BPF program
bpf_text_template = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include "opensnoop.h"

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);

// This is a hash map, but we use it as a set of
// process ids that are progeny of the ancestor id.
BPF_HASH(progeny_pids, u32, u32);

int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    FILTER
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        infotmp.update(&id, &val);
    }

    return 0;
};

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp;
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}

// IMPORTANT! Currently, this scheme only works for descendant
// processes that are added *after* opensnoop -f is run. To fix this,
// main.rs should insert the entire pstree into progeny_pids before
// starting the program.

int execve_entry()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;
    // Note this requires that we put the PID we are following
    // in progeny_pids before we attach any of the kprobes.
    if (progeny_pids.lookup(&ppid) != NULL) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        progeny_pids.update(&pid, &ppid);
    }

    return 0;
}

int exit_group_entry()
{
    // Note this does not account for child pids getting reparented if
    // they outlive their parent. Normally, they will get reparented to 1,
    // though apparently there are edge cases:
    // https://unix.stackexchange.com/questions/149319/new-parent-process-when-the-parent-process-dies
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    progeny_pids.delete(&pid);

    return 0;
}
"""


def gen_c(name, bpf_fn, filter_value="", placeholder=None):
    """Returns the C code for the function and the number of instructions in
    the array the C function generates."""
    bpf = BPF(text=bpf_text_template.replace("FILTER", filter_value))
    bytecode = bpf.dump_func(bpf_fn)
    bpf.cleanup()  # Reset fds before next BPF is created.
    num_insns = len(bytecode) / 8
    c_code, rust_code = generate_c_function(
        name, bytecode, num_insns, placeholder=placeholder
    )
    return c_code, rust_code, num_insns


PLACEHOLDER_TID = 123456
PLACEHOLDER_PID = 654321

# Note that we cannot call gen_c() while another file is open
# (such as generated_bytecode.h) or else it will throw off the
# file descriptor numbers in the generated code.
c_entry, rust_entry, entry_size, = gen_c("generate_trace_entry", "trace_entry")
c_execve_entry, rust_execve_entry, execve_entry_size, = gen_c(
    "generate_execve_entry", "execve_entry"
)
c_exit_group_entry, rust_exit_group_entry, exit_group_entry_size, = gen_c(
    "generate_exit_group_entry", "exit_group_entry"
)
c_entry_progeny, rust_entry_progeny, entry_progeny_size = gen_c(
    "generate_trace_entry_progeny",
    "trace_entry",
    filter_value="if (progeny_pids.lookup(&pid) == NULL) { return 0; }",
)
c_entry_tid, rust_entry_tid, entry_tid_size = gen_c(
    "generate_trace_entry_tid",
    "trace_entry",
    filter_value="if (tid != %d) { return 0; }" % PLACEHOLDER_TID,
    placeholder={"param_type": "int", "param_name": "tid", "imm": PLACEHOLDER_TID},
)
c_entry_pid, rust_entry_pid, entry_pid_size = gen_c(
    "generate_trace_entry_pid",
    "trace_entry",
    filter_value="if (pid != %d) { return 0; }" % PLACEHOLDER_PID,
    placeholder={"param_type": "int", "param_name": "pid", "imm": PLACEHOLDER_PID},
)
c_ret, rust_ret, ret_size = gen_c("generate_trace_return", "trace_return")

c_file = (
    (
        """\
// GENERATED FILE: See opensnoop.py.
#include <bcc/libbpf.h>
#include <stdlib.h>

#define MAX_NUM_TRACE_ENTRY_INSTRUCTIONS %d
#define NUM_TRACE_ENTRY_INSTRUCTIONS %d

#define NUM_TRACE_ENTRY_PROGENY_INSTRUCTIONS %d
#define NUM_EXECVE_ENTRY_INSTRUCTIONS %d
#define NUM_EXIT_GROUP_ENTRY_INSTRUCTIONS %d

#define NUM_TRACE_ENTRY_TID_INSTRUCTIONS %d
#define NUM_TRACE_ENTRY_PID_INSTRUCTIONS %d
#define NUM_TRACE_RETURN_INSTRUCTIONS %d

"""
        % (
            max(entry_size, entry_progeny_size, entry_tid_size, entry_pid_size),
            entry_size,
            entry_progeny_size,
            execve_entry_size,
            exit_group_entry_size,
            entry_tid_size,
            entry_pid_size,
            ret_size,
        )
    )
    + c_entry
    + c_entry_progeny
    + c_execve_entry
    + c_exit_group_entry
    + c_entry_tid
    + c_entry_pid
    + c_ret
)

__dir = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(__dir, "generated_bytecode.h"), "w") as f:
    f.write(c_file)

rust_file = (
    (
        """\
// GENERATED FILE: See opensnoop.py.
extern crate libbpf;

use libbpf::BpfMap;

pub const MAX_NUM_TRACE_ENTRY_INSTRUCTIONS: usize = %d;
pub const NUM_TRACE_ENTRY_INSTRUCTIONS: usize = %d;

pub const NUM_TRACE_ENTRY_PROGENY_INSTRUCTIONS: usize = %d;
pub const NUM_EXECVE_ENTRY_INSTRUCTIONS: usize = %d;
pub const NUM_EXIT_GROUP_ENTRY_INSTRUCTIONS: usize = %d;

pub const NUM_TRACE_ENTRY_TID_INSTRUCTIONS: usize = %d;
pub const NUM_TRACE_ENTRY_PID_INSTRUCTIONS: usize = %d;
pub const NUM_TRACE_RETURN_INSTRUCTIONS: usize = %d;
"""
        % (
            max(entry_size, entry_progeny_size, entry_tid_size, entry_pid_size),
            entry_size,
            entry_progeny_size,
            execve_entry_size,
            exit_group_entry_size,
            entry_tid_size,
            entry_pid_size,
            ret_size,
        )
    )
    + rust_entry
    + rust_entry_progeny
    + rust_execve_entry
    + rust_exit_group_entry
    + rust_entry_tid
    + rust_entry_pid
    + rust_ret
)

with open(os.path.join(__dir, "rust/opensnoop/src/generated_bytecode.rs"), "w") as f:
    f.write(rust_file)
