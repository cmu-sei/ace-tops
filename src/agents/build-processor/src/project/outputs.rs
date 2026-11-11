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

//! Build outputs: what a build produced — files, SBOMs and the dependency
//! graph they describe, binaries, container images.
//!
//! Reported by the build that produced them (instrumented pipeline stages,
//! `scripts/pipeline/core`).
//!
//! ```text
//! (BuildArtifact | Sbom | Binary | OCIArtifact)-[:IS]->(Artifact)
//! (BuildJob)-[:PRODUCED]->(BuildArtifact)
//! (BuildArtifact)-[:ANALYZED_AS]->(Sbom)                     sbom files
//! (BuildArtifact)-[:INSTANCE_OF]->(OCIArtifact)              pushed images
//! (Sbom)-[:DESCRIBES]->(Package)                             its root
//! (Sbom)-[:ASSERTS]->(DependencyTree)                        its own tree
//! (DependencyTree)-[:INCLUDES {direct}]->(Package)
//! (Binary)-[:BUILT_FROM]->(Package),  (Sbom)-[:ATTESTS]->(Binary)
//! (OCIArtifact)-[:HAS_DIFF_ID {order}]->(OCILayerDiffId)
//! ```
//!
//! Events about the same nodes may arrive in any order (e.g. BinaryLinked
//! before SbomAnalyzed). Every write MERGEs on identity, so whichever arrives
//! first creates the node and the other completes it.

use super::{edge, upsert};
use neo4rs::BoltType;
use polar::graph::controller::{GraphOp, GraphValue, Property, rel};
use polar::graph::nodes::builds::{ArtifactNodeKey, BuildNodeKey};
use polar::{
    ArtifactProducedPayload, BinaryLinkedPayload, ContainerImageCreatedPayload, PackageRef,
    SbomGraphFragment,
};
use std::collections::BTreeSet;
use tracing::{debug, trace, warn};

fn string(s: impl Into<String>) -> GraphValue {
    GraphValue::String(s.into())
}

/// Whether a reference names a package as the graph keys one: a purl (`pkg:type/name@version`). A CycloneDX
/// bom-ref that is not a purl (cargo-cyclonedx's `path+file://...#0.1.0`) names an entry of one SBOM, not a package,
/// and the producer is to give dependencies by purl (scripts/pipeline/core/sbom.nu, `extract-graph-fragment`).
fn is_purl(reference: &str) -> bool {
    reference.starts_with("pkg:")
}

/// What `node` IS: an artifact (pipeline-design-reference.md, "The type-marker singleton idiom").
fn type_edge(node: ArtifactNodeKey) -> GraphOp {
    edge(node, rel::IS, ArtifactNodeKey::Artifact, vec![])
}

/// A file the pipeline produced, keyed by content hash. Some artifact types
/// also get a node in their own domain:
/// - `sbom`: linked to the `Sbom` node that SbomAnalyzed writes for the same hash.
/// - `elf-binary`: a `Binary` node, which BinaryLinked attaches BUILT_FROM to.
/// - `oci-image`: the hash is the pushed manifest digest, so it is the
///   `OCIArtifact` the resolver records when the image is pulled.
pub fn artifact_produced(p: ArtifactProducedPayload) -> Vec<GraphOp> {
    trace!("ArtifactProduced: {} ({})", p.name, p.artifact_type);

    let artifact = ArtifactNodeKey::BuildArtifact {
        content_hash: p.artifact_content_hash.clone(),
    };
    let mut props = vec![Property("artifact_type".into(), string(&p.artifact_type))];
    if !p.name.is_empty() {
        props.push(Property("name".into(), string(&p.name)));
    }
    if !p.content_type.is_empty() {
        props.push(Property("content_type".into(), string(&p.content_type)));
    }

    let mut ops = vec![upsert(artifact.clone(), props), type_edge(artifact.clone())];

    match p.artifact_type.as_str() {
        // Connects "this pipeline produced this file" to "this file describes
        // package Y, which depends on Z".
        "sbom" => ops.push(edge(
            artifact.clone(),
            rel::ANALYZED_AS,
            ArtifactNodeKey::Sbom {
                artifact_content_hash: p.artifact_content_hash.clone(),
            },
            vec![],
        )),
        "elf-binary" => {
            let binary = ArtifactNodeKey::Binary {
                content_hash: p.artifact_content_hash.clone(),
            };
            let mut props = vec![Property("artifact_type".into(), string(&p.artifact_type))];
            if !p.name.is_empty() {
                props.push(Property("name".into(), string(&p.name)));
            }
            ops.push(upsert(binary.clone(), props));
            ops.push(type_edge(binary));
        }
        "oci-image" => ops.push(edge(
            artifact.clone(),
            rel::INSTANCE_OF,
            ArtifactNodeKey::OCIArtifact {
                digest: p.artifact_content_hash.clone(),
            },
            vec![],
        )),
        _ => {}
    }

    // Pipeline emissions always carry build_id; observer emissions don't.
    if let Some(build_id) = p.build_id {
        ops.push(edge(
            BuildNodeKey::BuildJob { build_id },
            rel::PRODUCED,
            artifact,
            vec![],
        ));
    }
    ops
}

/// What an SBOM's tree left out, each named in the tree's `gaps`: the root has no entry of its own in the tree, so
/// what it depends on directly is not known.
pub const NO_ROOT_ENTRY: &str = "no-root-entry";
/// A component the SBOM lists has no purl: it is no package, and the extraction left out its edges.
pub const COMPONENTS_WITHOUT_PURL: &str = "components-without-purl";
/// A dependency edge names something that is not a purl, and is not in the tree.
pub const REFS_NOT_PURLS: &str = "refs-not-purls";

/// The version of the form a tree's digest is taken over. A change to the form is a new version, so that one digest
/// never has two meanings.
const TREE_FORM: &str = "polar.dependency-tree/1";

/// The dependency tree one SBOM asserts: its own word on what its root depends on, apart from every other SBOM's, so
/// two builds' trees can be diffed (Blitz's risk-gradients.md, slice 2).
///
/// It is content-addressed. The digest is a sha256 over the canonical form, the JSON of
/// `[TREE_FORM, root, complete, gaps, packages, pairs]`, each set sorted and without repeats, so the same tree is
/// one digest whatever order the SBOM gave it in, and an unchanged tree is one node whichever builds assert it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertedTree {
    /// `sha256:` and the hex of the canonical form's sha256.
    pub digest: String,
    /// The purl of the package the SBOM describes.
    pub root: String,
    /// Nothing the SBOM said was left out: `gaps` is empty.
    pub complete: bool,
    /// What was left out ([`NO_ROOT_ENTRY`], [`COMPONENTS_WITHOUT_PURL`], [`REFS_NOT_PURLS`]).
    pub gaps: BTreeSet<&'static str>,
    /// Every package in the tree but its root: the components, and both ends of every pair.
    pub packages: BTreeSet<String>,
    /// Every (from, to) dependency, between purls.
    pub pairs: BTreeSet<(String, String)>,
    /// The packages the root depends on directly. `None` when the tree is incomplete: not known, rather than none.
    pub direct: Option<BTreeSet<String>>,
}

/// The tree an SBOM asserts, or none when it names no root: trees are compared by their root, and a tree with none
/// could not be. The SBOM's packages are written all the same.
pub fn asserted_tree(fragment: &SbomGraphFragment) -> Option<AssertedTree> {
    let root = fragment
        .root
        .as_ref()
        .map(|r| &r.purl)
        .filter(|p| is_purl(p))?
        .clone();

    let mut gaps = BTreeSet::new();
    if fragment.components.iter().any(|c| !is_purl(&c.purl)) {
        gaps.insert(COMPONENTS_WITHOUT_PURL);
    }
    let mut pairs = BTreeSet::new();
    for entry in &fragment.edges {
        for to in &entry.to_refs {
            if is_purl(&entry.from_ref) && is_purl(to) {
                pairs.insert((entry.from_ref.clone(), to.clone()));
            } else {
                gaps.insert(REFS_NOT_PURLS);
            }
        }
    }
    // Pairs may name purls the components do not list; they are in the tree all the same.
    let packages: BTreeSet<String> = fragment
        .components
        .iter()
        .map(|c| &c.purl)
        .filter(|p| is_purl(p))
        .chain(pairs.iter().flat_map(|(from, to)| [from, to]))
        .filter(|p| **p != root)
        .cloned()
        .collect();
    // A root that depends on nothing has no entry: the tree is the root alone, and nothing is missing.
    if !packages.is_empty() && !fragment.edges.iter().any(|e| e.from_ref == root) {
        gaps.insert(NO_ROOT_ENTRY);
    }

    let complete = gaps.is_empty();
    let direct = complete.then(|| {
        pairs
            .iter()
            .filter(|(from, _)| *from == root)
            .map(|(_, to)| to.clone())
            .collect()
    });
    let form = (TREE_FORM, &root, complete, &gaps, &packages, &pairs);
    let canonical =
        serde_json::to_vec(&form).expect("strings, a bool and sets of strings serialize");
    Some(AssertedTree {
        digest: format!("sha256:{}", polar::artifact_uid_from_bytes(&canonical)),
        root,
        complete,
        gaps,
        packages,
        pairs,
        direct,
    })
}

/// The writes for the tree an SBOM asserts: the tree, keyed by its digest, with its pairs as two aligned lists
/// (`edges_from[i]` depends on `edges_to[i]`), the SBOM's ASSERTS edge to it, and its INCLUDES edge to each package,
/// `direct` unset when that is not known.
///
/// The raw Cypher must agree with `ArtifactNodeKey::DependencyTree`'s label and key (`DependencyTree {digest}`) and
/// with `ArtifactNodeKey::Package`'s (`Package {purl}`).
fn tree_ops(sbom: ArtifactNodeKey, tree: AssertedTree) -> Vec<GraphOp> {
    let key = ArtifactNodeKey::DependencyTree {
        digest: tree.digest.clone(),
    };
    let strings =
        |xs: Vec<String>| GraphValue::List(xs.into_iter().map(GraphValue::String).collect());
    let (from, to): (Vec<String>, Vec<String>) = tree.pairs.into_iter().unzip();
    let props = vec![
        Property("root".into(), string(&tree.root)),
        Property("complete".into(), GraphValue::Bool(tree.complete)),
        Property(
            "gaps".into(),
            strings(tree.gaps.iter().map(|g| g.to_string()).collect()),
        ),
        Property("edges_from".into(), strings(from)),
        Property("edges_to".into(), strings(to)),
    ];
    let rows: Vec<GraphValue> = tree
        .packages
        .iter()
        .map(|purl| {
            let direct = match &tree.direct {
                Some(direct) => GraphValue::Bool(direct.contains(purl)),
                None => GraphValue::Null,
            };
            GraphValue::Map(vec![
                ("purl".into(), string(purl)),
                ("direct".into(), direct),
            ])
        })
        .collect();

    let mut ops = vec![
        upsert(key.clone(), props),
        edge(sbom, rel::ASSERTS, key, vec![]),
    ];
    if !rows.is_empty() {
        ops.push(GraphOp::RawMergeWrite {
            cypher: format!(
                "UNWIND $rows AS row \
                 MERGE (t:DependencyTree {{ digest: $digest }}) \
                 MERGE (p:Package {{ purl: row.purl }}) \
                 MERGE (t)-[r:{rel}]->(p) \
                 SET r.direct = row.direct",
                rel = rel::INCLUDES,
            ),
            params: vec![
                ("digest".to_string(), BoltType::from(tree.digest)),
                ("rows".to_string(), BoltType::from(GraphValue::List(rows))),
            ],
        });
    }
    ops
}

/// An SBOM and the dependency graph it describes.
///
/// The package rows and dependency edges are batched into one UNWIND query
/// each, so one SBOM is a handful of transactions rather than one per
/// package. Each query is atomic on its own; the SBOM as a whole is not.
/// Full-SBOM atomicity would need a multi-statement transaction, which is
/// deliberately not done here to keep each query verifiable by eye.
///
/// The raw Cypher must agree with `ArtifactNodeKey::Package`'s label and key
/// (`Package {purl}`), since RawQuery bypasses the key's own Cypher.
pub fn sbom_analyzed(mut fragment: SbomGraphFragment) -> Vec<GraphOp> {
    trace!(
        "SbomAnalyzed: {} with {} components, {} edges",
        fragment.filename,
        fragment.components.len(),
        fragment.edges.len()
    );
    // Taken from the SBOM as it came, so the tree can name what the filtering below leaves out.
    let tree = asserted_tree(&fragment);

    // A package is keyed by its purl: an entry the generator gave none is not written, rather than merged with every
    // other such entry into one `Package { purl: "" }`.
    let listed = fragment.components.len();
    fragment.components.retain(|c| is_purl(&c.purl));
    let unnamed_root = fragment.root.take_if(|root| !is_purl(&root.purl)).is_some();
    if unnamed_root || fragment.components.len() < listed {
        warn!(
            "SBOM {}: {} components and {} root have no purl and are not written",
            fragment.filename,
            listed - fragment.components.len(),
            if unnamed_root { "its" } else { "no" }
        );
    }

    let sbom = ArtifactNodeKey::Sbom {
        artifact_content_hash: fragment.artifact_content_hash.clone(),
    };
    let mut ops = vec![
        upsert(
            sbom.clone(),
            vec![Property("filename".into(), string(&fragment.filename))],
        ),
        type_edge(sbom.clone()),
    ];

    // The root is upserted with the other packages below (MERGE dedupes on
    // purl); only the DESCRIBES edge is written here.
    if let Some(ref root) = fragment.root {
        ops.push(edge(
            sbom.clone(),
            rel::DESCRIBES,
            ArtifactNodeKey::Package {
                purl: root.purl.clone(),
            },
            vec![],
        ));
    }

    // ── Package nodes, root included ─────────────────────────────────────────
    // license and source are intrinsic to a (name, version), so they belong on
    // the Package node (unlike scope, which is relative to one SBOM and would
    // belong on an edge). An SBOM that gives none says nothing about them, so it does not erase what another gave.
    let opt_str = |v: &Option<String>| match v {
        Some(s) => GraphValue::String(s.clone()),
        None => GraphValue::Null,
    };
    let package_row = |p: &PackageRef| {
        GraphValue::Map(vec![
            ("purl".into(), string(&p.purl)),
            ("name".into(), string(&p.name)),
            ("version".into(), string(&p.version)),
            ("component_type".into(), string(&p.component_type)),
            ("license".into(), opt_str(&p.license)),
            ("source".into(), opt_str(&p.source)),
        ])
    };
    let rows: Vec<GraphValue> = fragment
        .root
        .iter()
        .chain(&fragment.components)
        .map(package_row)
        .collect();
    if !rows.is_empty() {
        ops.push(GraphOp::RawMergeWrite {
            cypher: "UNWIND $rows AS row \
                 MERGE (p:Package { purl: row.purl }) \
                 SET p.name = row.name, \
                     p.version = row.version, \
                     p.component_type = row.component_type, \
                     p.license = coalesce(row.license, p.license), \
                     p.source = coalesce(row.source, p.source)"
                .to_string(),
            params: vec![("rows".to_string(), BoltType::from(GraphValue::List(rows)))],
        });
    }

    // ── The tree this SBOM asserts ───────────────────────────────────────────
    // Its own word, apart from every other SBOM's: no global DEPENDS_ON web, in which two builds' trees run
    // together and cannot be diffed.
    let edge_count = match tree {
        Some(tree) => {
            if !tree.complete {
                warn!(
                    "SBOM {}: its dependency tree is incomplete ({}), so what {} depends on directly is not known",
                    fragment.filename,
                    tree.gaps.iter().copied().collect::<Vec<_>>().join(", "),
                    tree.root,
                );
            }
            let count = tree.pairs.len();
            ops.extend(tree_ops(sbom, tree));
            count
        }
        None => {
            warn!(
                "SBOM {} names no root, so it asserts no dependency tree",
                fragment.filename
            );
            0
        }
    };

    debug!(
        "SbomAnalyzed: {} package nodes + a tree of {} dependency edges for {}",
        fragment.components.len() + fragment.root.iter().count(),
        edge_count,
        fragment.filename,
    );
    ops
}

/// A compiled binary, linked to the package it was built from and the SBOM
/// describing that package's dependencies. If this arrives before the SBOM,
/// MERGE creates a purl-only Package that SbomAnalyzed fills in later.
pub fn binary_linked(p: BinaryLinkedPayload, observed_at: &str) -> Vec<GraphOp> {
    trace!("BinaryLinked: {} -> {}", p.binary_name, p.root_purl);

    let binary = ArtifactNodeKey::Binary {
        content_hash: p.binary_content_hash.clone(),
    };
    let package = ArtifactNodeKey::Package {
        purl: p.root_purl.clone(),
    };

    let mut props = vec![
        Property("name".into(), string(&p.binary_name)),
        Property("observed_at".into(), string(observed_at)),
    ];
    if !p.binding_digest.is_empty() {
        props.push(Property("binding_digest".into(), string(&p.binding_digest)));
    }

    let mut ops = vec![
        upsert(binary.clone(), props),
        type_edge(binary.clone()),
        upsert(package.clone(), vec![]),
        edge(binary.clone(), rel::BUILT_FROM, package, vec![]),
    ];
    // A direct edge for convenience: Binary → Package ← Sbom is already
    // traversable, but this records that *this* SBOM describes *this* binary.
    if !p.sbom_content_hash.is_empty() {
        ops.push(edge(
            ArtifactNodeKey::Sbom {
                artifact_content_hash: p.sbom_content_hash.clone(),
            },
            rel::ATTESTS,
            binary,
            vec![],
        ));
    }
    debug!(
        "BinaryLinked: {} ({}) -> {}",
        p.binary_name, p.binary_content_hash, p.root_purl
    );
    ops
}

/// A container image the pipeline built and pushed, keyed by its pushed
/// manifest `digest`: the same `OCIArtifact` the resolver records when the
/// image is pulled, so build and registry facts land on one node.
///
/// Layers are recorded as the image config identifies them, by
/// *uncompressed* diff ID, under `HAS_DIFF_ID {order}`. The resolver records
/// the same layers as registry blobs, by *compressed* digest, under
/// `HAS_LAYER {order}` (see `registry`). Matching `order` on one artifact
/// pairs the two identities of a layer.
///
/// Without a digest there is no registry identity to key on; the event is
/// skipped rather than merging every such image into one `digest: ""` node.
pub fn container_image_created(p: ContainerImageCreatedPayload) -> Vec<GraphOp> {
    trace!(
        "ContainerImageCreated: {} ({} layers)",
        p.image_name,
        p.layers.len()
    );
    if p.digest.is_empty() {
        warn!(
            image = %p.image_name,
            "ContainerImageCreated without a manifest digest — not recorded"
        );
        return vec![];
    }

    let image = ArtifactNodeKey::OCIArtifact {
        digest: p.digest.clone(),
    };

    let mut props = vec![
        Property("name".into(), string(&p.image_name)),
        Property("tarball_hash".into(), string(&p.tarball_hash)),
        Property("uri".into(), string(&p.uri)),
    ];
    for (key, value) in [
        ("os", &p.os),
        ("arch", &p.arch),
        ("created", &p.created),
        ("entrypoint", &p.entrypoint),
        ("cmd", &p.cmd),
    ] {
        if !value.is_empty() {
            props.push(Property(key.into(), string(value)));
        }
    }
    // Comma-separated: tags are informational, not identity, and Neo4j list
    // properties are awkward under MERGE.
    if !p.repo_tags.is_empty() {
        props.push(Property("repo_tags".into(), string(p.repo_tags.join(","))));
    }

    let mut ops = vec![upsert(image.clone(), props), type_edge(image.clone())];
    for layer in &p.layers {
        let diff_id = ArtifactNodeKey::OCILayerDiffId {
            diff_id: layer.diff_id.clone(),
        };
        ops.push(upsert(diff_id.clone(), vec![]));
        ops.push(edge(
            image.clone(),
            rel::HAS_DIFF_ID,
            diff_id,
            vec![Property(
                "order".into(),
                GraphValue::I64(layer.order as i64),
            )],
        ));
    }
    debug!(
        "ContainerImageCreated: {} with {} layers (config: {})",
        p.image_name,
        p.layers.len(),
        p.config_digest,
    );
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar::DependencyEdge;
    use polar::graph::controller::compile_graph_op;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    const ROOT: &str = "pkg:cargo/polar@1.0.0";
    const ITOA: &str = "pkg:cargo/itoa@1.0.18";
    const RYU: &str = "pkg:cargo/ryu@1.0.20";
    const SERDE: &str = "pkg:cargo/serde@1.0.228";

    fn package(purl: &str) -> PackageRef {
        PackageRef {
            purl: purl.into(),
            name: String::new(),
            version: String::new(),
            component_type: "library".into(),
            license: None,
            source: None,
        }
    }

    /// An SBOM's fragment: its root, its components, and its tree from (from, to) pairs, one entry per `from` in the
    /// order first given, a pair given twice listed twice.
    fn sbom(
        hash: &str,
        root: Option<&str>,
        components: &[&str],
        pairs: &[(&str, &str)],
    ) -> SbomGraphFragment {
        let mut edges: Vec<DependencyEdge> = vec![];
        for &(from, to) in pairs {
            match edges.iter_mut().find(|e| e.from_ref == from) {
                Some(entry) => entry.to_refs.push(to.into()),
                None => edges.push(DependencyEdge {
                    from_ref: from.into(),
                    to_refs: vec![to.into()],
                }),
            }
        }
        SbomGraphFragment {
            artifact_content_hash: hash.into(),
            filename: format!("{hash}.cdx.json"),
            root: root.map(package),
            components: components.iter().map(|c| package(c)).collect(),
            edges,
        }
    }

    fn digest(fragment: &SbomGraphFragment) -> String {
        asserted_tree(fragment).expect("a tree").digest
    }

    /// The INCLUDES rows written: each package's purl and whether the root depends on it directly (`None`: not known).
    fn includes(ops: &[GraphOp]) -> BTreeMap<String, Option<bool>> {
        let mut rows = BTreeMap::new();
        for op in ops {
            let GraphOp::RawMergeWrite { cypher, params } = op else {
                continue;
            };
            if !cypher.contains(rel::INCLUDES) {
                continue;
            }
            let Some((_, BoltType::List(list))) = params.iter().find(|(k, _)| k == "rows") else {
                panic!("INCLUDES without rows: {cypher}");
            };
            for row in &list.value {
                let BoltType::Map(row) = row else {
                    panic!("a row that is not a map: {row:?}");
                };
                let Some(BoltType::String(purl)) = row.value.get("purl") else {
                    panic!("a row without a purl: {row:?}");
                };
                let direct = match row.value.get("direct") {
                    Some(BoltType::Boolean(b)) => Some(b.value),
                    Some(BoltType::Null(_)) | None => None,
                    other => panic!("direct is {other:?}"),
                };
                assert!(
                    rows.insert(purl.value.clone(), direct).is_none(),
                    "{} included twice",
                    purl.value
                );
            }
        }
        rows
    }

    /// The DependencyTree node written, by its props.
    fn tree_node(ops: &[GraphOp]) -> Option<BTreeMap<String, GraphValue>> {
        ops.iter().find_map(|op| match op {
            GraphOp::UpsertNode { key, props } if key.identity().labels == ["DependencyTree"] => {
                Some(
                    props
                        .iter()
                        .map(|Property(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )
            }
            _ => None,
        })
    }

    fn strings(xs: &[&str]) -> GraphValue {
        GraphValue::List(xs.iter().map(|x| string(*x)).collect())
    }

    #[test]
    fn a_complete_tree_is_asserted_and_includes_each_package_once() {
        let fragment = sbom(
            "sha256:sbom",
            Some(ROOT),
            &[ITOA, RYU, SERDE, ITOA],
            &[(ROOT, ITOA), (ROOT, RYU), (ITOA, SERDE), (ITOA, SERDE)],
        );
        let tree = asserted_tree(&fragment).unwrap();
        assert!(tree.complete && tree.gaps.is_empty(), "{tree:?}");
        assert_eq!(tree.root, ROOT);
        assert_eq!(
            tree.direct,
            Some([ITOA, RYU].iter().map(|p| p.to_string()).collect())
        );
        assert!(tree.digest.starts_with("sha256:") && tree.digest.len() == 7 + 64);

        let ops = sbom_analyzed(fragment);
        let node = tree_node(&ops).expect("no DependencyTree written");
        assert_eq!(node["root"], string(ROOT));
        assert_eq!(node["complete"], GraphValue::Bool(true));
        assert_eq!(node["gaps"], GraphValue::List(vec![]));
        // Sorted by (from, to), the two lists aligned: (itoa, serde), (polar, itoa), (polar, ryu).
        assert_eq!(node["edges_from"], strings(&[ITOA, ROOT, ROOT]));
        assert_eq!(node["edges_to"], strings(&[SERDE, ITOA, RYU]));
        assert_eq!(
            includes(&ops),
            BTreeMap::from([
                (ITOA.to_string(), Some(true)),
                (RYU.to_string(), Some(true)),
                (SERDE.to_string(), Some(false)),
            ])
        );
        let asserts = ops.iter().any(|op| {
            matches!(op, GraphOp::EnsureEdge { from, rel_type, to, .. }
                if from.identity().labels == ["Sbom"]
                    && rel_type == rel::ASSERTS
                    && to.identity().labels == ["DependencyTree"])
        });
        assert!(asserts, "no (Sbom)-[:ASSERTS]->(DependencyTree)");
        for op in &ops {
            compile_graph_op(op).unwrap_or_else(|e| panic!("the controller refuses {op:?}: {e}"));
        }
    }

    /// The tree is each build's own word; the global `DEPENDS_ON` web, every SBOM's edges run together, is not written.
    #[test]
    fn a_projected_sbom_writes_no_depends_on() {
        for fragment in [
            sbom(
                "sha256:a",
                Some(ROOT),
                &[ITOA, SERDE],
                &[(ROOT, ITOA), (ITOA, SERDE)],
            ),
            sbom("sha256:b", Some(ROOT), &[ITOA, SERDE], &[(ITOA, SERDE)]),
            sbom("sha256:c", None, &[ITOA, SERDE], &[(ITOA, SERDE)]),
        ] {
            let written = format!("{:?}", sbom_analyzed(fragment));
            assert!(!written.contains("DEPENDS_ON"), "{written}");
        }
    }

    #[test]
    fn a_root_with_no_entry_asserts_an_incomplete_tree_and_no_flat_edges() {
        let fragment = sbom("sha256:sbom", Some(ROOT), &[ITOA, RYU], &[(ITOA, RYU)]);
        let tree = asserted_tree(&fragment).unwrap();
        assert!(!tree.complete);
        assert_eq!(tree.gaps, BTreeSet::from([NO_ROOT_ENTRY]));
        assert_eq!(tree.direct, None, "direct is unknown, not none");

        let ops = sbom_analyzed(fragment);
        let node = tree_node(&ops).expect("no DependencyTree written");
        assert_eq!(node["complete"], GraphValue::Bool(false));
        assert_eq!(node["gaps"], strings(&[NO_ROOT_ENTRY]));
        // The root is not linked to every component: it is linked to nothing, and the tree says why.
        assert_eq!(node["edges_from"], strings(&[ITOA]));
        assert_eq!(
            includes(&ops),
            BTreeMap::from([(ITOA.to_string(), None), (RYU.to_string(), None)])
        );
    }

    #[test]
    fn what_an_sbom_leaves_out_is_named_in_its_trees_gaps() {
        let fragment = sbom(
            "sha256:sbom",
            Some(ROOT),
            &[ITOA, ""],
            &[(ROOT, ITOA), (ROOT, "path+file:///work/vendored#0.1.0")],
        );
        let tree = asserted_tree(&fragment).unwrap();
        assert!(!tree.complete);
        assert_eq!(
            tree.gaps,
            BTreeSet::from([COMPONENTS_WITHOUT_PURL, REFS_NOT_PURLS])
        );
        assert_eq!(tree.direct, None);
        assert_eq!(tree.packages, BTreeSet::from([ITOA.to_string()]));
    }

    /// A root that depends on nothing has no entry (the extraction leaves out an entry with nothing in it), and the
    /// tree is just the root: complete, not a gap.
    #[test]
    fn a_root_with_nothing_to_depend_on_is_a_complete_tree() {
        let fragment = sbom("sha256:sbom", Some(ROOT), &[], &[]);
        let tree = asserted_tree(&fragment).unwrap();
        assert!(tree.complete && tree.packages.is_empty(), "{tree:?}");
        assert_eq!(tree.direct, Some(BTreeSet::new()));
        let ops = sbom_analyzed(fragment);
        assert!(tree_node(&ops).is_some());
        assert!(includes(&ops).is_empty());
    }

    #[test]
    fn an_sbom_with_no_root_asserts_no_tree() {
        for root in [None, Some(""), Some("path+file:///work/polar#0.1.0")] {
            let fragment = sbom("sha256:sbom", root, &[ITOA], &[]);
            assert_eq!(asserted_tree(&fragment), None, "root {root:?}");
            let written = format!("{:?}", sbom_analyzed(fragment));
            assert!(
                !written.contains("DependencyTree"),
                "root {root:?}: {written}"
            );
            assert!(
                written.contains(ITOA),
                "its packages are written all the same"
            );
        }
    }

    /// A redelivered event writes nothing new: the same tree, and every write a MERGE on identity.
    #[test]
    fn a_redelivered_sbom_asserts_the_same_tree_and_creates_nothing() {
        let fragment = || {
            sbom(
                "sha256:sbom",
                Some(ROOT),
                &[ITOA, RYU],
                &[(ROOT, ITOA), (ITOA, RYU)],
            )
        };
        assert_eq!(asserted_tree(&fragment()), asserted_tree(&fragment()));
        // Row maps are HashMaps, so a raw write is compared by its Cypher; the others by all they hold.
        let shape = |ops: Vec<GraphOp>| -> Vec<String> {
            ops.iter()
                .map(|op| match op {
                    GraphOp::RawMergeWrite { cypher, .. } => {
                        assert!(!cypher.contains("CREATE"), "{cypher}");
                        cypher.clone()
                    }
                    GraphOp::UpsertNode { .. } | GraphOp::EnsureEdge { .. } => format!("{op:?}"),
                    other => panic!("not a MERGE on identity: {other:?}"),
                })
                .collect()
        };
        assert_eq!(
            shape(sbom_analyzed(fragment())),
            shape(sbom_analyzed(fragment()))
        );
    }

    #[test]
    fn each_change_to_a_tree_changes_its_digest() {
        let base = sbom(
            "sha256:sbom",
            Some(ROOT),
            &[ITOA, RYU],
            &[(ROOT, ITOA), (ITOA, RYU)],
        );
        let bumped = "pkg:cargo/ryu@1.0.21";
        let trees = [
            base.clone(),
            // A dependency moved: ryu is the root's now, not itoa's.
            sbom(
                "sha256:sbom",
                Some(ROOT),
                &[ITOA, RYU],
                &[(ROOT, ITOA), (ROOT, RYU)],
            ),
            // A version bumped.
            sbom(
                "sha256:sbom",
                Some(ROOT),
                &[ITOA, bumped],
                &[(ROOT, ITOA), (ITOA, bumped)],
            ),
            // The same pairs, another root.
            sbom(
                "sha256:sbom",
                Some("pkg:cargo/other@1.0.0"),
                &[ITOA, RYU],
                &[(ROOT, ITOA), (ITOA, RYU)],
            ),
            // A component no edge names.
            sbom(
                "sha256:sbom",
                Some(ROOT),
                &[ITOA, RYU, SERDE],
                &[(ROOT, ITOA), (ITOA, RYU)],
            ),
            // The root's entry gone: incomplete.
            sbom("sha256:sbom", Some(ROOT), &[ITOA, RYU], &[(ITOA, RYU)]),
        ];
        let digests: BTreeSet<String> = trees.iter().map(digest).collect();
        assert_eq!(digests.len(), trees.len(), "{digests:?}");
        // What the SBOM file is (its hash, its name) is not the tree.
        let mut renamed = base.clone();
        renamed.artifact_content_hash = "sha256:other".into();
        renamed.filename = "other.cdx.json".into();
        assert_eq!(digest(&base), digest(&renamed));
    }

    /// Package `i` of a small alphabet; 0 is the root.
    fn purl(i: usize) -> String {
        format!("pkg:cargo/p{i}@1.0.0")
    }

    /// A fragment from indices, each pair its own entry, in the order given.
    fn indexed(components: &[usize], pairs: &[(usize, usize)]) -> SbomGraphFragment {
        SbomGraphFragment {
            artifact_content_hash: "sha256:sbom".into(),
            filename: "sbom.cdx.json".into(),
            root: Some(package(&purl(0))),
            components: components.iter().map(|&i| package(&purl(i))).collect(),
            edges: pairs
                .iter()
                .map(|&(from, to)| DependencyEdge {
                    from_ref: purl(from),
                    to_refs: vec![purl(to)],
                })
                .collect(),
        }
    }

    /// What a tree is, computed apart from `asserted_tree`: its pairs, its packages but the root, and whether the
    /// root's direct dependencies are known.
    fn model(
        components: &[usize],
        pairs: &[(usize, usize)],
    ) -> (BTreeSet<(usize, usize)>, BTreeSet<usize>, bool) {
        let pairs: BTreeSet<_> = pairs.iter().copied().collect();
        let packages: BTreeSet<usize> = components
            .iter()
            .copied()
            .chain(pairs.iter().flat_map(|&(a, b)| [a, b]))
            .filter(|&p| p != 0)
            .collect();
        let known = packages.is_empty() || pairs.iter().any(|&(from, _)| from == 0);
        (pairs, packages, known)
    }

    proptest! {
        /// The same tree is one digest, whatever order its entries, their dependencies and its components come in,
        /// however they are grouped into entries, and however often each is repeated.
        #[test]
        fn a_tree_has_one_digest_whatever_its_order(
            (pairs, shuffled) in proptest::collection::vec((0usize..6, 1usize..6), 0..16)
                .prop_flat_map(|p| (Just(p.clone()), Just(p).prop_shuffle())),
            components in proptest::collection::vec(1usize..6, 0..6),
        ) {
            // One entry per `from`, as a generator writes it.
            let mut grouped: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
            for &(from, to) in &pairs {
                grouped.entry(from).or_default().push(to);
            }
            let mut once = indexed(&components, &[]);
            once.edges = grouped
                .into_iter()
                .map(|(from, to)| DependencyEdge {
                    from_ref: purl(from),
                    to_refs: to.into_iter().map(purl).collect(),
                })
                .collect();
            let twice: Vec<_> = shuffled.iter().chain(shuffled.iter().rev()).copied().collect();
            let mut repeated: Vec<_> = components.iter().rev().copied().collect();
            repeated.extend(&components);
            prop_assert_eq!(digest(&once), digest(&indexed(&repeated, &twice)));
        }

        /// Two trees have one digest exactly when they are the same tree: the same pairs, packages and knowledge
        /// of the root's direct dependencies.
        #[test]
        fn trees_that_differ_have_different_digests(
            a_pairs in proptest::collection::vec((0usize..4, 1usize..4), 0..5),
            a_components in proptest::collection::vec(1usize..4, 0..3),
            b_pairs in proptest::collection::vec((0usize..4, 1usize..4), 0..5),
            b_components in proptest::collection::vec(1usize..4, 0..3),
        ) {
            let same = model(&a_components, &a_pairs) == model(&b_components, &b_pairs);
            let a = digest(&indexed(&a_components, &a_pairs));
            let b = digest(&indexed(&b_components, &b_pairs));
            prop_assert_eq!(a == b, same, "{} {}", a, b);
        }
    }
}
