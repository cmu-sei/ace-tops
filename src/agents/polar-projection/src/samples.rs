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

//! Samples beside a mapping, and what each becomes (docs/architecture/http-observers.md, "Evidence", bites 3 and 4). A
//! sample is `<name>.json`, a document as a service returns it, beside `<name>.expected.json`, what it becomes: the
//! nodes and edges it writes, without the stamps, and how many entries were skipped, or why it was refused. A kind's
//! tests (`polar-http-testkit`) and a deployment's (`polar-sign projection test`) both hold a mapping to them, read
//! with the sample's name as its source.

use crate::{NodeId, Outcome, Projection, STAMP_PREFIX, Scalar, Stamp, Write};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

/// A document as a service returns it, and what it should become.
#[derive(Debug)]
pub struct Sample {
    pub name: String,
    pub document: Vec<u8>,
    /// None when nothing is written beside it yet.
    pub expected: Option<Value>,
    pub expected_at: PathBuf,
}

/// How a sample's outcome differs from what is written beside it.
#[derive(Debug, PartialEq)]
pub enum Differs {
    /// Nothing is written beside it.
    Unwritten,
    /// It became `got`, and beside it is something else.
    Became {
        got: Box<Value>,
        expected: Box<Value>,
    },
}

/// Every sample in `dir`, by name. None is a problem: a mapping with no samples has not said what it does with the
/// documents a service returns.
pub fn read(dir: &Path) -> Result<Vec<Sample>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut names = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if let Some(name) = name.strip_suffix(".json")
            && !name.ends_with(".expected")
        {
            names.push(name.to_string());
        }
    }
    names.sort();
    if names.is_empty() {
        return Err(format!(
            "no samples in {}: a mapping says what it does with documents a service returns, as <name>.json",
            dir.display()
        ));
    }
    names
        .into_iter()
        .map(|name| {
            let at = |suffix: &str| dir.join(format!("{name}{suffix}"));
            let document = std::fs::read(at(".json"))
                .map_err(|e| format!("cannot read {}: {e}", at(".json").display()))?;
            let expected_at = at(".expected.json");
            let expected = match std::fs::read_to_string(&expected_at) {
                Ok(text) => Some(
                    serde_json::from_str(&text)
                        .map_err(|e| format!("{} is not JSON: {e}", expected_at.display()))?,
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(format!("cannot read {}: {e}", expected_at.display())),
            };
            Ok(Sample {
                name,
                document,
                expected,
                expected_at,
            })
        })
        .collect()
}

/// Where every sample is read from, so what one becomes does not depend on where a test served it.
pub const SAMPLE_ORIGIN: &str = "https://samples.example";

impl Sample {
    /// What the sample becomes under `projection`, read as the source of its name, at [`SAMPLE_ORIGIN`].
    pub fn outcome(&self, projection: &Projection, stamp: &Stamp<'_>) -> Outcome {
        let at = Stamp {
            origin: SAMPLE_ORIGIN,
            ..*stamp
        };
        projection.outcome(&self.name, &self.document, &at)
    }

    /// Whether `got`, what it became plainly, is what is written beside it.
    pub fn check(&self, got: &Value) -> Result<(), Differs> {
        match &self.expected {
            None => Err(Differs::Unwritten),
            Some(expected) if expected != got => Err(Differs::Became {
                got: Box::new(got.clone()),
                expected: Box::new(expected.clone()),
            }),
            Some(_) => Ok(()),
        }
    }

    /// Writes `got` beside the sample as what it becomes: read it before committing it, since it is then what is expected.
    pub fn bless(&self, got: &Value) -> Result<(), String> {
        let text = serde_json::to_string_pretty(got).map_err(|e| e.to_string())? + "\n";
        std::fs::write(&self.expected_at, text)
            .map_err(|e| format!("cannot write {}: {e}", self.expected_at.display()))
    }
}

impl Differs {
    /// Said in a line, without what the sample holds.
    pub fn briefly(&self, sample: &Sample) -> String {
        match self {
            Differs::Unwritten => format!(
                "`{}` has nothing beside it: write {} and read it before committing it",
                sample.name,
                sample.expected_at.display()
            ),
            Differs::Became { .. } => format!(
                "`{}` became other than {} says",
                sample.name,
                sample.expected_at.display()
            ),
        }
    }

    /// Said whole: what it became and what is written beside it.
    pub fn fully(&self, sample: &Sample) -> String {
        match self {
            Differs::Unwritten => self.briefly(sample),
            Differs::Became { got, expected } => format!(
                "`{}` became\n{}\nand {} says\n{}",
                sample.name,
                serde_json::to_string_pretty(got).unwrap_or_default(),
                sample.expected_at.display(),
                serde_json::to_string_pretty(expected).unwrap_or_default(),
            ),
        }
    }
}

fn scalar(value: &Scalar) -> Value {
    match value {
        Scalar::Text(s) => json!(s),
        Scalar::Bool(b) => json!(b),
        Scalar::Integer(i) => json!(i),
        Scalar::Real(r) => json!(r),
        Scalar::Null => Value::Null,
    }
}

fn plain_props(props: &[(String, Scalar)]) -> Map<String, Value> {
    props
        .iter()
        .filter(|(name, _)| !name.starts_with(STAMP_PREFIX))
        .map(|(name, value)| (name.clone(), scalar(value)))
        .collect()
}

fn plain_id(id: &NodeId) -> Value {
    json!({ "label": id.label, "keys": plain_props(&id.keys) })
}

/// `value` as text with every object's names in order.
fn ordered(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut names: Vec<&String> = map.keys().collect();
            names.sort();
            let fields: Vec<String> = names
                .into_iter()
                .map(|name| format!("{}:{}", json!(name), ordered(&map[name])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(ordered).collect();
            format!("[{}]", items.join(","))
        }
        other => other.to_string(),
    }
}

/// What a document became, written plainly for a person to review: each node by its label and keys with what it sets (a
/// null clears what was there), each edge by its ends and type, and how many entries could not be identified; or why it
/// was refused. Without the stamps, which a property holds to what they should be.
pub fn plainly(outcome: &Outcome) -> Value {
    match outcome {
        Outcome::Refused(why) => json!({ "refused": why }),
        Outcome::Write { writes, skipped } => {
            let mut nodes = Vec::new();
            let mut edges = Vec::new();
            for write in writes {
                match write {
                    Write::Node { id, props } => {
                        let mut node = plain_id(id);
                        node["set"] = Value::Object(plain_props(props));
                        nodes.push(node);
                    }
                    Write::Edge {
                        from,
                        to,
                        kind,
                        props,
                    } => {
                        let mut edge =
                            json!({ "from": plain_id(from), "type": kind, "to": plain_id(to) });
                        let set = plain_props(props);
                        if !set.is_empty() {
                            edge["set"] = Value::Object(set);
                        }
                        edges.push(edge);
                    }
                }
            }
            // In the order of what identifies each, with every object's names sorted, so the order is the same whether or
            // not the build keeps JSON objects in insertion order.
            nodes.sort_by_key(|n| ordered(&json!([n["label"], n["keys"]])));
            edges.sort_by_key(|e| ordered(&json!([e["from"], e["type"], e["to"]])));
            json!({ "skipped": skipped, "nodes": nodes, "edges": edges })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/openapi")
    }

    const STAMP: Stamp<'static> = Stamp {
        workload: "w",
        version: 1,
        observed_at_unix_secs: 1,
        origin: "https://elsewhere.example",
    };

    /// The example's samples, read through the example mapping, are what is written beside them; the kit holds the
    /// same through the real handler and signing path.
    #[test]
    fn each_example_becomes_what_is_written_beside_it() {
        let projection = Projection::well_formed(&crate::tests::openapi_body()).unwrap();
        let samples = read(&examples()).unwrap();
        let names: Vec<&str> = samples.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "no-paths",
                "not-the-document",
                "openapi-3.0",
                "openapi-3.1",
                "swagger-2.0"
            ]
        );
        for sample in &samples {
            let got = plainly(&sample.outcome(&projection, &STAMP));
            assert_eq!(sample.check(&got), Ok(()), "{}", sample.name);
        }
    }

    #[test]
    fn a_sample_is_read_by_its_name_and_a_document_beside_it_or_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).unwrap_err().contains("no samples"));
        std::fs::write(dir.path().join("b.json"), "{}").unwrap();
        std::fs::write(dir.path().join("a.json"), "[]").unwrap();
        std::fs::write(dir.path().join("a.expected.json"), r#"{"refused":"x"}"#).unwrap();
        std::fs::write(dir.path().join("notes.txt"), "not a sample").unwrap();
        let samples = read(dir.path()).unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(
            (samples[0].name.as_str(), &samples[0].document[..]),
            ("a", &b"[]"[..])
        );
        assert_eq!(samples[0].expected, Some(json!({ "refused": "x" })));
        assert_eq!(samples[1].name, "b");
        assert_eq!(samples[1].expected, None);
        assert_eq!(samples[1].check(&json!({})), Err(Differs::Unwritten));

        std::fs::write(dir.path().join("b.expected.json"), "not json").unwrap();
        assert!(read(dir.path()).unwrap_err().contains("is not JSON"));
    }

    #[test]
    fn a_sample_blessed_is_then_what_it_is_checked_against() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s.json"), "{}").unwrap();
        let got = json!({ "skipped": 0, "nodes": [], "edges": [] });
        let other = json!({ "refused": "no" });
        read(dir.path()).unwrap()[0].bless(&got).unwrap();
        let sample = &read(dir.path()).unwrap()[0];
        assert_eq!(sample.check(&got), Ok(()));
        let differs = sample.check(&other).unwrap_err();
        assert_eq!(
            differs,
            Differs::Became {
                got: Box::new(other.clone()),
                expected: Box::new(got)
            }
        );
        assert!(
            !differs.briefly(sample).contains("refused"),
            "a line says nothing the sample holds"
        );
        assert!(differs.fully(sample).contains("refused"));
    }

    #[test]
    fn plainly_leaves_out_the_stamps_and_orders_what_is_written() {
        let id = |n: &str| NodeId {
            label: "L".into(),
            keys: vec![
                ("k".into(), Scalar::Text(n.into())),
                ("polar_source".into(), Scalar::Text("s".into())),
            ],
        };
        let node = |n: &str| Write::Node {
            id: id(n),
            props: vec![
                ("p".into(), Scalar::Null),
                ("polar_workload".into(), Scalar::Text("w".into())),
            ],
        };
        let edge = Write::Edge {
            from: id("a"),
            to: id("b"),
            kind: "HAS".into(),
            props: vec![("polar_version".into(), Scalar::Integer(1))],
        };
        let outcome = Outcome::Write {
            writes: vec![node("b"), edge, node("a")],
            skipped: 2,
        };
        let plain = |n: &str| json!({ "label": "L", "keys": { "k": n } });
        assert_eq!(
            plainly(&outcome),
            json!({
                "skipped": 2,
                "nodes": [
                    { "label": "L", "keys": { "k": "a" }, "set": { "p": null } },
                    { "label": "L", "keys": { "k": "b" }, "set": { "p": null } },
                ],
                "edges": [ { "from": plain("a"), "type": "HAS", "to": plain("b") } ],
            })
        );
        assert_eq!(
            plainly(&Outcome::Refused("why".into())),
            json!({ "refused": "why" })
        );
        let mut reversed = Map::new();
        reversed.insert("b".into(), json!(1));
        reversed.insert("a".into(), json!([{ "d": 2, "c": 3 }]));
        assert_eq!(
            ordered(&Value::Object(reversed)),
            r#"{"a":[{"c":3,"d":2}],"b":1}"#
        );
    }
}
