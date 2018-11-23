use regex::Regex;
use std::collections::HashSet;
use std::process::Command;

// https://unix.stackexchange.com/questions/67668/elegantly-get-list-of-descendant-processes

pub fn get_descendants(pid: u32) -> HashSet<u32> {
  let output = Command::new("pstree")
    .arg("-T")
    .arg("-p")
    .arg(pid.to_string())
    .output()
    .expect("failed to execute pstree");
  if !output.status.success() {
    panic!("pstree exited with {}", output.status);
  } else {
    parse_pstree_output(&String::from_utf8_lossy(&output.stdout))
  }
}

fn parse_pstree_output(output: &str) -> HashSet<u32> {
  let mut pids = HashSet::new();
  let re = Regex::new(r"\((\d+)\)").unwrap();
  for cap in re.captures_iter(output) {
    pids.insert(cap[1].parse::<u32>().unwrap());
  }
  pids
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn verify_parse_pstree_output() {
    let pstree_output = r#"
chrome(26485)─┬─cat(26491)
              ├─cat(26492)
              ├─chrome(26495)─┬─chrome(26501)─┬─chrome(1047)
              │               │               ├─chrome(1911)
              │               │               ├─chrome(2352)
              │               └─nacl_helper(26498)───nacl_helper(26854)
              └─chrome(26527)───chrome(26545)
    "#;
    let pids = parse_pstree_output(pstree_output);
    let expected_pids: HashSet<u32> = [
      26485, 26491, 26492, 26495, 26501, 1047, 1911, 2352, 26498, 26854, 26527, 26545,
    ]
      .iter()
      .cloned()
      .collect();
    assert_eq!(pids, expected_pids);
  }
}
