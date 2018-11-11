mod raw_libbpf;

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::raw::c_int;
use std::os::unix::io::FromRawFd;

pub enum BpfMapType {
  Unspec,
  Hash,
  Array,
  ProgArray,
  PerfEventArray,
  PerCpuHash,
  PerCpuArray,
  StackTrace,
  CgroupArray,
  LruHash,
  LruPerCpuHash,
  LpmTrie,
  ArrayOfMaps,
  HashOfMaps,
  DevMap,
  SockMap,
  CpuMap,
  XskMap,
  SockHash,
  CgroupStorage,
  ReusePortSockArray,
}

fn to_map_type(bpf_map_type: BpfMapType) -> raw_libbpf::bpf_map_type {
  #![allow(non_snake_case)]
  match bpf_map_type {
    BpfMapType::Unspec => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_UNSPEC,
    BpfMapType::Hash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_HASH,
    BpfMapType::Array => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_ARRAY,
    BpfMapType::ProgArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY,
    BpfMapType::PerfEventArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BpfMapType::PerCpuHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH,
    BpfMapType::PerCpuArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY,
    BpfMapType::StackTrace => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_STACK_TRACE,
    BpfMapType::CgroupArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_CGROUP_ARRAY,
    BpfMapType::LruHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_LRU_HASH,
    BpfMapType::LruPerCpuHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BpfMapType::LpmTrie => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_LPM_TRIE,
    BpfMapType::ArrayOfMaps => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BpfMapType::HashOfMaps => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_HASH_OF_MAPS,
    BpfMapType::DevMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_DEVMAP,
    BpfMapType::SockMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_SOCKMAP,
    BpfMapType::CpuMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_CPUMAP,
    BpfMapType::XskMap => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_XSKMAP,
    BpfMapType::SockHash => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_SOCKHASH,
    BpfMapType::CgroupStorage => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_CGROUP_STORAGE,
    BpfMapType::ReusePortSockArray => raw_libbpf::bpf_map_type_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
  }
}

#[derive(Debug)]
pub struct BpfMap {
  /// Wrap the fd as a File so that it is automatically closed when it goes out
  /// of scope.
  fd: File,
}

pub fn bpf_create_map<K, V>(bpf_map_type: BpfMapType, max_entries: c_int) -> io::Result<BpfMap> {
  let key_size = size_of::<K>() as i32;
  let value_size = size_of::<V>() as i32;
  // TODO: Create a typesafe enum for map flags and make it a param.
  let map_flags: c_int = 0;
  let name = CString::new("not currently configurable").unwrap();
  let map_fd = unsafe {
    raw_libbpf::bpf_create_map(
      to_map_type(bpf_map_type),
      name.as_ptr(),
      key_size,
      value_size,
      max_entries,
      map_flags,
    )
  };

  if map_fd >= 0 {
    let file = unsafe { File::from_raw_fd(map_fd) };
    Ok(BpfMap { fd: file })
  } else if map_fd == -1 {
    Err(io::Error::last_os_error())
  } else {
    panic!("Unexpected value from bpf_create_map(): {}", map_fd)
  }
}
