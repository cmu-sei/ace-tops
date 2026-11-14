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

//! The Polar git client (docs/architecture/polar-git.md): a git remote helper, so `git clone polar://tools`, `git push`
//! and the rest of git work against polar-git as against any git server. git hands a `polar://` URL to this program; it
//! names polar-git's HTTPS address for the repository and gives git the person's Polar certificate, its key and Polar's
//! CA, then hands over to git's own HTTPS transport (`git remote-https`), which speaks to polar-git from there. Nothing is
//! kept or changed outside the one git command it serves.
//!
//! What it takes, each from the environment first and then from git's configuration:
//! - who: `POLAR_USER`, or `polar.user`; their certificate is `<user>.crt` and `<user>.key` beside `ca.pem` in
//!   `POLAR_ADMIN_DIR`, or `~/.config/polar-admin`, as polar-sign and polar-eden find them;
//! - where: a URL's own host (`polar://host:port/repo`), or `POLAR_GIT_HOST`, or `polar.host`, or polar-git's name in the
//!   cluster, `polar-git.polar.svc.cluster.local:8443`;
//! - how to reach it through a forward: `POLAR_GIT_RESOLVE`, or `polar.resolve` (`host:port:address`, curl's form).

use std::path::{Path, PathBuf};

/// polar-git's name in the cluster, and its port.
pub const DEFAULT_HOST: &str = "polar-git.polar.svc.cluster.local:8443";

/// Where a `polar://` URL points: polar-git's host and port, and the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: Option<String>,
    pub repo: String,
}

/// The repository a `polar://` URL names, and the host if it names one: `polar://tools`, `polar://host:8443/tools`,
/// `polar:///tools`. A repository name with a `/`, or none, is refused.
pub fn parse(url: &str) -> Result<Target, String> {
    let rest = url
        .strip_prefix("polar://")
        .ok_or_else(|| format!("{url} is not a polar:// URL"))?;
    let (host, repo) = match rest.split_once('/') {
        Some((host, repo)) => ((!host.is_empty()).then(|| host.to_string()), repo),
        None => (None, rest),
    };
    let repo = repo.trim_end_matches('/');
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if repo.is_empty() || repo.contains('/') {
        return Err(format!(
            "{url} does not name one repository (polar://[host:port/]name)"
        ));
    }
    Ok(Target {
        host,
        repo: repo.to_string(),
    })
}

/// What the helper looks things up in: the environment, then git's configuration.
pub trait Lookup {
    fn env(&self, name: &str) -> Option<String>;
    fn git_config(&self, key: &str) -> Option<String>;
}

/// The address git is handed, and the configuration it is given for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub https_url: String,
    pub config: Vec<(String, String)>,
}

fn first(lookup: &dyn Lookup, env: &str, key: &str) -> Option<String> {
    lookup
        .env(env)
        .or_else(|| lookup.git_config(key))
        .filter(|v| !v.trim().is_empty())
}

/// What git is to do for `url`, with the person's certificate under `home`'s `.config/polar-admin` unless told
/// otherwise.
pub fn plan(url: &str, lookup: &dyn Lookup, home: Option<&Path>) -> Result<Plan, String> {
    let target = parse(url)?;
    let host = target
        .host
        .clone()
        .or_else(|| first(lookup, "POLAR_GIT_HOST", "polar.host"))
        .unwrap_or_else(|| DEFAULT_HOST.to_string());
    let user = first(lookup, "POLAR_USER", "polar.user").ok_or(
        "who is pushing is not known: set POLAR_USER, or `git config --global polar.user <your username>`",
    )?;
    let dir = lookup
        .env("POLAR_ADMIN_DIR")
        .map(PathBuf::from)
        .or_else(|| home.map(|h| h.join(".config/polar-admin")))
        .ok_or("no POLAR_ADMIN_DIR, and no home to find ~/.config/polar-admin in")?;
    let https_url = format!("https://{host}/{}.git", target.repo);
    let mut config = git_config(&dir, &user);
    if let Some(resolve) = first(lookup, "POLAR_GIT_RESOLVE", "polar.resolve") {
        config.push(("http.curloptResolve".to_string(), resolve));
    }
    Ok(Plan { https_url, config })
}

/// The person's certificate and key, and Polar's CA, as `just admin-claim` leaves them in `dir` (`ca.pem`, `<user>.crt`,
/// `<user>.key`), for git's own HTTPS transport: git reads them, and this program never opens a key.
fn git_config(dir: &Path, user: &str) -> Vec<(String, String)> {
    [
        ("http.sslCAInfo", "ca.pem".to_string()),
        ("http.sslCert", format!("{user}.crt")),
        ("http.sslKey", format!("{user}.key")),
    ]
    .into_iter()
    .map(|(key, name)| {
        (
            key.to_string(),
            dir.join(name).to_string_lossy().to_string(),
        )
    })
    .collect()
}

/// `config` as git takes configuration from its environment (`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`,
/// `GIT_CONFIG_VALUE_<n>`), after any `already` given there.
pub fn config_env(config: &[(String, String)], already: usize) -> Vec<(String, String)> {
    let mut env = vec![(
        "GIT_CONFIG_COUNT".to_string(),
        (already + config.len()).to_string(),
    )];
    for (n, (key, value)) in config.iter().enumerate() {
        env.push((format!("GIT_CONFIG_KEY_{}", already + n), key.clone()));
        env.push((format!("GIT_CONFIG_VALUE_{}", already + n), value.clone()));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Given {
        env: HashMap<String, String>,
        config: HashMap<String, String>,
    }

    impl Lookup for Given {
        fn env(&self, name: &str) -> Option<String> {
            self.env.get(name).cloned()
        }
        fn git_config(&self, key: &str) -> Option<String> {
            self.config.get(key).cloned()
        }
    }

    fn given(env: &[(&str, &str)], config: &[(&str, &str)]) -> Given {
        Given {
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            config: config
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn a_polar_url_names_one_repository_and_may_name_a_host() {
        assert_eq!(
            parse("polar://tools").unwrap(),
            Target {
                host: None,
                repo: "tools".into()
            }
        );
        assert_eq!(parse("polar://tools.git").unwrap().repo, "tools");
        assert_eq!(
            parse("polar://git.example:9443/tools").unwrap(),
            Target {
                host: Some("git.example:9443".into()),
                repo: "tools".into()
            }
        );
        assert_eq!(
            parse("polar:///tools/").unwrap(),
            Target {
                host: None,
                repo: "tools".into()
            }
        );
        for bad in [
            "https://x/tools",
            "polar://",
            "polar://host/",
            "polar://host/a/b",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    /// git is given polar-git's address and the person's certificate, key and Polar's CA, and a way through a forward
    /// when one is set; the environment comes before git's configuration.
    #[test]
    fn git_is_given_polar_gits_address_and_the_persons_certificate() {
        let lookup = given(
            &[("POLAR_USER", "alice")],
            &[
                ("polar.user", "bob"),
                (
                    "polar.resolve",
                    "polar-git.polar.svc.cluster.local:8443:127.0.0.1",
                ),
            ],
        );
        let planned = plan("polar://tools", &lookup, Some(Path::new("/home/a"))).unwrap();
        assert_eq!(
            planned.https_url,
            "https://polar-git.polar.svc.cluster.local:8443/tools.git"
        );
        assert_eq!(
            planned.config,
            vec![
                (
                    "http.sslCAInfo".to_string(),
                    "/home/a/.config/polar-admin/ca.pem".to_string()
                ),
                (
                    "http.sslCert".to_string(),
                    "/home/a/.config/polar-admin/alice.crt".to_string()
                ),
                (
                    "http.sslKey".to_string(),
                    "/home/a/.config/polar-admin/alice.key".to_string()
                ),
                (
                    "http.curloptResolve".to_string(),
                    "polar-git.polar.svc.cluster.local:8443:127.0.0.1".to_string()
                ),
            ]
        );
        let elsewhere = plan(
            "polar://tools",
            &given(
                &[("POLAR_ADMIN_DIR", "/keys"), ("POLAR_GIT_HOST", "h:1")],
                &[("polar.user", "bob")],
            ),
            None,
        )
        .unwrap();
        assert_eq!(elsewhere.https_url, "https://h:1/tools.git");
        assert_eq!(elsewhere.config[1].1, "/keys/bob.crt");
        assert_eq!(elsewhere.config.len(), 3, "no forward set, no resolve");
    }

    #[test]
    fn without_a_user_nothing_is_planned_and_how_to_set_one_is_said() {
        let err = plan(
            "polar://tools",
            &given(&[], &[]),
            Some(Path::new("/home/a")),
        )
        .unwrap_err();
        assert!(err.contains("polar.user"), "{err}");
        let err = plan("polar://tools", &given(&[("POLAR_USER", "a")], &[]), None).unwrap_err();
        assert!(err.contains("polar-admin"), "{err}");
    }

    #[test]
    fn the_configuration_is_numbered_after_any_already_given() {
        let config = vec![
            ("a.b".to_string(), "1".to_string()),
            ("c.d".to_string(), "2".to_string()),
        ];
        assert_eq!(
            config_env(&config, 2),
            vec![
                ("GIT_CONFIG_COUNT".to_string(), "4".to_string()),
                ("GIT_CONFIG_KEY_2".to_string(), "a.b".to_string()),
                ("GIT_CONFIG_VALUE_2".to_string(), "1".to_string()),
                ("GIT_CONFIG_KEY_3".to_string(), "c.d".to_string()),
                ("GIT_CONFIG_VALUE_3".to_string(), "2".to_string()),
            ]
        );
    }
}
