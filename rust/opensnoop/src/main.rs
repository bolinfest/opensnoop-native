extern crate libbpf;
extern crate libc;
extern crate nix;
extern crate regex;
extern crate structopt;

mod bindings;
mod generated_bytecode;
mod pstree;

use generated_bytecode::generate_execve_entry;
use generated_bytecode::generate_exit_group_entry;
use generated_bytecode::generate_trace_entry;
use generated_bytecode::generate_trace_entry_pid;
use generated_bytecode::generate_trace_entry_progeny;
use generated_bytecode::generate_trace_entry_tid;
use generated_bytecode::generate_trace_return;
use generated_bytecode::MAX_NUM_TRACE_ENTRY_INSTRUCTIONS;
use generated_bytecode::NUM_EXECVE_ENTRY_INSTRUCTIONS;
use generated_bytecode::NUM_EXIT_GROUP_ENTRY_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_ENTRY_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_ENTRY_PID_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_ENTRY_PROGENY_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_ENTRY_TID_INSTRUCTIONS;
use generated_bytecode::NUM_TRACE_RETURN_INSTRUCTIONS;
use libbpf::bpf_attach_kprobe;
use libbpf::bpf_create_map;
use libbpf::bpf_insn;
use libbpf::bpf_open_perf_buffer;
use libbpf::bpf_prog_load;
use libbpf::perf_reader_fd;
use libbpf::perf_reader_poll;
use libbpf::BpfProbeAttachType;
use libbpf::BpfProg;
use libbpf::BpfProgType;
use nix::fcntl;
use nix::unistd;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::os::raw::c_int;
use std::os::raw::c_void;
use std::os::unix::io::FromRawFd;
use std::process;
use structopt::StructOpt;

// Next steps:
// - Refactor main() so it is not one enormous fn.
// - Add perf_reader_free() cleanup.
// - Accept args so opensnoop can spawn a process and --follow it like strace.

const NANOS_PER_SECOND: f32 = 1_000_000_000.0;

#[derive(StructOpt)]
#[structopt(name = "opensnoop")]
struct Options {
  #[structopt(
    long = "timestamp",
    short = "T",
    help = "include timestamp on output"
  )]
  timestamp: bool,

  #[structopt(
    long = "failed",
    short = "x",
    help = "only show failed opens"
  )]
  failed: bool,

  #[structopt(long = "pid", short = "p", help = "trace this PID only")]
  pid: Option<u32>,

  #[structopt(long = "tid", short = "t", help = "trace this TID only")]
  tid: Option<u32>,

  #[structopt(
    long = "duration",
    short = "d",
    help = "total duration of trace in seconds"
  )]
  duration: Option<u32>,

  #[structopt(
    long = "name",
    short = "n",
    help = "only print process names containing this name"
  )]
  name: Option<String>,

  #[structopt(
    long = "follow",
    short = "f",
    help = "trace -p PID and its descendant processes"
  )]
  follow: bool,

  // TODO(mbolin): What is it about the way I'm using execv(2) that
  // the command does not seem to be evaluated in the context of
  // my $PATH? I can pass `/bin/ls` but not `ls`.
  #[structopt(name = "COMMAND")]
  command: Vec<String>,
}

enum ProcessFilter {
  NoFilter,
  Pid {
    pid: u32,
    follow: bool,
    fd: Option<File>,
  },
  Tid(u32),
}

struct DisplayOptions {
  show_pid_header: bool,
  timestamp: bool,
  failed: bool,
  duration: Option<u32>,
  name: Option<String>,
}

struct ProcessedOptions {
  filter: ProcessFilter,
  display: DisplayOptions,
}

struct PerfReaderCallbackContext<'a> {
  options: &'a DisplayOptions,
  initial_timestamp: u64,
}

/// Maintains references to additional kprobes when --follow is specified
/// in order to keep their fds open.
#[allow(dead_code)]
struct ProgenyProgs {
  execve_prog: BpfProg,
  execve_kprobe: libbpf::Kprobe,
  exit_group_prog: BpfProg,
  exit_group_kprobe: libbpf::Kprobe,
}

fn create_process_filter(
  options: Options,
) -> std::result::Result<ProcessFilter, Box<std::error::Error>> {
  // Incidentally, this function could return io::Error or nix::Error.
  // The lack of built-in support for converting between the two is
  // deliberate: https://github.com/nix-rust/nix/issues/613. I know I
  // need to read the docs for the failure crate, but I haven't had a
  // chance yet.
  if options.follow && options.pid.is_none() {
    eprint!("Error: -p must be specified when -f is specified.\n");
    process::exit(1);
  }

  if !options.command.is_empty() {
    // Spawn a subprocess and make it the PID of the returned options.
    let pipe = unistd::pipe2(fcntl::OFlag::O_CLOEXEC)?;
    match unistd::fork()? {
      unistd::ForkResult::Parent { child, .. } => {
        let _rc = unsafe { libc::close(pipe.0) };
        let pid = libc::pid_t::from(child) as u32;
        let file = unsafe { File::from_raw_fd(pipe.1) };
        Ok(ProcessFilter::Pid {
          pid,
          follow: options.follow,
          fd: Some(file),
        })
      }
      unistd::ForkResult::Child => {
        let _rc = unsafe {
          libc::close(pipe.1);
        };

        // Do not exec until the pipe is written to by the parent.
        let mut file = unsafe { File::from_raw_fd(pipe.0) };
        let mut buf: [u8; 1] = [0];
        file.read_exact(&mut buf)?;
        let _rc = unsafe {
          libc::close(pipe.0);
        };

        // TODO(mbolin): Figure out how to eliminate the use of clone() here.
        let (left, right) = options.command.split_first().unwrap();
        let command = CString::new(left.clone())?;
        let mut args: Vec<CString> = vec![command.clone()];
        args.extend(right.iter().map(|x| CString::new(x.clone()).unwrap()));
        unistd::execv(&command, &args)?;
        panic!("execv should not return")
      }
    }
  } else if let Some(tid) = options.tid {
    Ok(ProcessFilter::Tid(tid))
  } else if let Some(pid) = options.pid {
    Ok(ProcessFilter::Pid {
      pid,
      follow: options.follow,
      fd: None,
    })
  } else {
    Ok(ProcessFilter::NoFilter)
  }
}

fn process_options() -> std::result::Result<ProcessedOptions, Box<std::error::Error>> {
  let options = Options::from_args();
  let timestamp = options.timestamp.clone();
  let failed = options.failed.clone();
  let duration = options.duration.clone();
  let name = options.name.clone();
  let filter = create_process_filter(options)?;
  let show_pid_header = match &filter {
    ProcessFilter::NoFilter | ProcessFilter::Pid { .. } => true,
    ProcessFilter::Tid(_) => false,
  };
  let display = DisplayOptions {
    show_pid_header,
    timestamp,
    failed,
    duration,
    name,
  };
  Ok(ProcessedOptions { filter, display })
}

fn main() -> std::result::Result<(), Box<std::error::Error>> {
  let options = process_options()?;

  // This value comes from the BPF_HASH() macro in bcc.
  let max_entries = 10240;
  let val_map = bpf_create_map::<u64, bindings::val_t>(libbpf::BpfMapType::Hash, max_entries)?;

  let cpus = get_online_cpus()?;
  let perf_map = bpf_create_map::<i32, u32>(libbpf::BpfMapType::PerfEventArray, cpus.len() as i32)?;

  let progeny_pids = bpf_create_map::<u32, u32>(libbpf::BpfMapType::Hash, max_entries)?;

  let mut instructions: [bpf_insn; MAX_NUM_TRACE_ENTRY_INSTRUCTIONS] =
    unsafe { mem::uninitialized() };
  let (num_instructions, _progeny_progs) = match options.filter {
    ProcessFilter::NoFilter => {
      generate_trace_entry(&mut instructions, &val_map);
      (NUM_TRACE_ENTRY_INSTRUCTIONS, None)
    }
    ProcessFilter::Tid(tid) => {
      generate_trace_entry_tid(&mut instructions, tid as i32, &val_map);
      (NUM_TRACE_ENTRY_TID_INSTRUCTIONS, None)
    }
    ProcessFilter::Pid { pid, follow, .. } => {
      if follow {
        let mut dummy_value = 1;
        for pid in pstree::get_descendants(pid) {
          let mut pid_value = pid;
          let pid_ptr = &mut pid_value as *mut _ as *mut std::ffi::c_void;
          let value_ptr = &mut dummy_value as *mut _ as *mut std::ffi::c_void;
          progeny_pids.update(pid_ptr, value_ptr)?;
        }

        let mut execve_instructions: [bpf_insn; NUM_EXECVE_ENTRY_INSTRUCTIONS] =
          unsafe { mem::uninitialized() };
        generate_execve_entry(&mut execve_instructions, &progeny_pids);
        let execve_prog = bpf_prog_load(
          BpfProgType::Kprobe,
          execve_instructions.as_ptr(),
          NUM_EXECVE_ENTRY_INSTRUCTIONS as i32,
        )?;
        let execve_kprobe = bpf_attach_kprobe(
          &execve_prog,
          BpfProbeAttachType::Entry,
          CString::new("p_sys_execve").unwrap().as_ptr(),
          CString::new("sys_execve").unwrap().as_ptr(),
          None,
        )?;

        let mut exit_group_instructions: [bpf_insn; NUM_EXIT_GROUP_ENTRY_INSTRUCTIONS] =
          unsafe { mem::uninitialized() };
        generate_exit_group_entry(&mut exit_group_instructions, &progeny_pids);
        let exit_group_prog = bpf_prog_load(
          BpfProgType::Kprobe,
          exit_group_instructions.as_ptr(),
          NUM_EXIT_GROUP_ENTRY_INSTRUCTIONS as i32,
        )?;
        let exit_group_kprobe = bpf_attach_kprobe(
          &exit_group_prog,
          BpfProbeAttachType::Entry,
          CString::new("p_sys_exit_group").unwrap().as_ptr(),
          CString::new("sys_exit_group").unwrap().as_ptr(),
          None,
        )?;

        let progs = ProgenyProgs {
          execve_prog,
          execve_kprobe,
          exit_group_prog,
          exit_group_kprobe,
        };

        generate_trace_entry_progeny(&mut instructions, &val_map, &progeny_pids);
        (NUM_TRACE_ENTRY_PROGENY_INSTRUCTIONS, Some(progs))
      } else {
        generate_trace_entry_pid(&mut instructions, pid as i32, &val_map);
        (NUM_TRACE_ENTRY_PID_INSTRUCTIONS, None)
      }
    }
  };
  let entry_prog = bpf_prog_load(
    BpfProgType::Kprobe,
    instructions.as_ptr(),
    num_instructions as i32,
  )?;
  let _kprobe = bpf_attach_kprobe(
    &entry_prog,
    BpfProbeAttachType::Entry,
    CString::new("p_do_sys_open").unwrap().as_ptr(),
    CString::new("do_sys_open").unwrap().as_ptr(),
    None,
  )?;

  let mut ret_instructions: [bpf_insn; NUM_TRACE_RETURN_INSTRUCTIONS] =
    unsafe { mem::uninitialized() };
  generate_trace_return(&mut ret_instructions, &val_map, &perf_map);
  let return_prog = bpf_prog_load(
    BpfProgType::Kprobe,
    ret_instructions.as_ptr(),
    NUM_TRACE_RETURN_INSTRUCTIONS as c_int,
  )?;
  let _kretprobe = bpf_attach_kprobe(
    &return_prog,
    BpfProbeAttachType::Return,
    CString::new("r_do_sys_open").unwrap().as_ptr(),
    CString::new("do_sys_open").unwrap().as_ptr(),
    None,
  )?;

  // Now that all of the probes have been attached, notify the child process, if
  // appropriate.
  if let ProcessFilter::Pid {
    fd: Some(mut file), ..
  } = options.filter
  {
    let buf: [u8; 1] = [1];
    file.write_all(&buf)?;
    // TODO: Verify that file is dropped and therefore closed here.
  }

  // Open a perf buffer for each online CPU.
  // (This is what open_perf_buffer() in bcc/table.py does.)
  let mut readers: Vec<*mut libbpf::perf_reader> = Vec::with_capacity(cpus.len());
  let mut context = PerfReaderCallbackContext {
    options: &options.display,
    initial_timestamp: 0,
  };
  for (i, cpu) in cpus.iter().enumerate() {
    let reader = unsafe {
      bpf_open_perf_buffer(
        /* raw_cb */ Some(perf_reader_raw_callback),
        /* lost_cb */ None,
        /* cb_cookie */ &mut context as *mut _ as *mut std::ffi::c_void,
        /* pid */ -1,
        *cpu as i32,
        /* page_cnt */ 64,
      )
    };
    if reader.is_null() {
      panic!("Error calling bpf_open_perf_buffer()");
    }

    let mut perf_reader_fd = unsafe { perf_reader_fd(reader as *mut libbpf::perf_reader) };
    readers.push(reader as *mut libbpf::perf_reader);
    // https://stackoverflow.com/q/34691267/396304
    let perf_reader_fd_ptr = &mut perf_reader_fd as *mut _ as *mut std::ffi::c_void;
    perf_map.update(
      unsafe { (cpus.as_ptr().offset(i as isize)) } as *mut std::ffi::c_void,
      perf_reader_fd_ptr,
    )?;
  }

  if options.display.timestamp {
    print!("{:14}", "TIME(s)");
  }
  let pid_or_tid = if options.display.show_pid_header {
    "PID"
  } else {
    "TID"
  };
  println!(
    "{:6} {:16} {:4} {:3} {}",
    pid_or_tid, "COMM", "FD", "ERR", "PATH"
  );

  let end_time = if let Some(duration) = options.display.duration {
    let mut time = libc::timespec {
      tv_sec: 0,
      tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut time) };
    check_unix_error(rc)?;

    time.tv_sec += duration as i64;
    Some(time)
  } else {
    None
  };

  // TODO(mbolin): Also break when the process dies if user is only tracing a single process.
  loop {
    if let Some(end_time) = end_time {
      let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
      };
      let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut current_time) };
      check_unix_error(rc)?;

      if current_time.tv_sec > end_time.tv_sec
        || (current_time.tv_sec == end_time.tv_sec && current_time.tv_nsec >= end_time.tv_nsec)
      {
        break;
      }
    }

    let rc = unsafe { perf_reader_poll(cpus.len() as i32, readers.as_mut_ptr(), -1) };
    check_unix_error(rc)?;
  }

  Ok(())
}

fn get_online_cpus() -> io::Result<Vec<u32>> {
  let mut f = File::open("/sys/devices/system/cpu/online")?;
  let mut buffer = String::new();
  f.read_to_string(&mut buffer)?;
  Ok(read_cpu_ranges(&buffer.trim_end()))
}

fn read_cpu_ranges(cpu_ranges: &str) -> Vec<u32> {
  let mut cpus: Vec<u32> = vec![];
  for cpu_range in cpu_ranges.split(",") {
    if let Some(index) = cpu_range.find("-") {
      let start: u32 = cpu_range[..index].parse::<u32>().unwrap();
      let end: u32 = cpu_range[(index + 1)..].parse::<u32>().unwrap();
      for cpu in start..(end + 1) {
        cpus.push(cpu);
      }
    } else {
      let cpu = cpu_range.parse::<u32>().unwrap();
      cpus.push(cpu);
    }
  }
  cpus
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn verify_read_cpu_ranges() {
    assert_eq!(read_cpu_ranges("1-4"), vec![1, 2, 3, 4]);
    assert_eq!(read_cpu_ranges("1-4,9-12"), vec![1, 2, 3, 4, 9, 10, 11, 12]);
    assert_eq!(read_cpu_ranges("7"), vec![7]);
    assert_eq!(read_cpu_ranges("7,9-12"), vec![7, 9, 10, 11, 12]);
  }
}

extern "C" fn perf_reader_raw_callback(cb_cookie: *mut c_void, raw: *mut c_void, _raw_size: c_int) {
  let context = unsafe { &mut *(cb_cookie as *mut PerfReaderCallbackContext) };
  let options = context.options;
  let event = unsafe { &*(raw as *mut bindings::data_t) };
  let ret = event.ret;

  if options.failed && ret >= 0 {
    return;
  }

  if let Some(ref name) = options.name {
    let comm = (unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) }).to_string_lossy();
    if !comm.contains(name.as_str()) {
      return;
    }
  }

  let (fd_s, err) = if ret >= 0 { (ret, 0) } else { (-1, -ret) };

  if options.timestamp {
    if context.initial_timestamp == 0 {
      context.initial_timestamp = event.ts;
    }

    let delta = event.ts - context.initial_timestamp;
    print!("{:<14.9}", delta as f32 / NANOS_PER_SECOND);
  }

  let id = if options.show_pid_header {
    (event.id >> 32) as u32
  } else {
    event.id as u32
  };
  println!(
    "{:6} {:16} {:4} {:3} {}",
    id,
    (unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) }).to_string_lossy(),
    fd_s,
    err,
    (unsafe { std::ffi::CStr::from_ptr(event.fname.as_ptr()) }).to_string_lossy(),
  );
}

fn check_unix_error(rc: c_int) -> io::Result<()> {
  if rc == -1 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}
