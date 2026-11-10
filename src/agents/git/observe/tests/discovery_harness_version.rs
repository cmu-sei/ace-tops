/*
   ACE Tool

   Copyright 2026 Carnegie Mellon University.

   NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
   FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
   EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
   PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
   MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
   TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   Licensed under a MIT (SEI)-style license, please see license.txt or contact
   permission@sei.cmu.edu for full terms.

   [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
   distribution.  Please see Copyright notice for non-US Government use and distribution.

   This Software includes and/or makes use of Third-Party Software each subject to its own license.

   DM26-0670
*/

//! `git-discovery-harness --version`: the platform's line, and with `--json` the record (polar-version), answered before the discovery harness
//! reaches for a repository or the broker. Run with an empty environment, so a build that does not answer it fails on what it lacks instead.

fn run(args: &[&str]) -> (Option<i32>, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_git-discovery-harness"))
        .args(args)
        .env_clear()
        .output()
        .expect("run git-discovery-harness");
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
    )
}

#[test]
fn version_is_the_platform_record() {
    let record = polar_version::record("git-discovery-harness");
    assert_eq!(
        run(&["--version"]),
        (Some(0), format!("{}\n", record.line()))
    );
    assert_eq!(
        run(&["--version", "--json"]),
        (Some(0), format!("{}\n", record.json()))
    );
}
