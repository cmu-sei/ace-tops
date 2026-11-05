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

//! What a name must be to stand in Cypher as a label, a relationship type or a property name. Cypher parameterizes
//! property values only, so a name is the one thing interpolated into a query's text, and this is what stands between a
//! name and that text. The graph controller holds every query to it (`polar::graph::controller`); a mapping is held to it
//! before it is signed (`polar-projection`), by the same rule.

/// Cypher keywords that would be dangerous to interpolate directly into
/// a query as a label, relationship type, or property name -- not
/// exhaustive against every reserved word, but covers every keyword that
/// could actually mutate or destroy data if smuggled in this way.
pub const KEYWORD_BLACKLIST: &[&str] = &[
    "MATCH",
    "MERGE",
    "CREATE",
    "DELETE",
    "DETACH",
    "SET",
    "REMOVE",
    "RETURN",
    "WHERE",
    "WITH",
    "UNWIND",
    "CALL",
    "YIELD",
    "FOREACH",
    "LOAD",
    "CSV",
    "UNION",
    "OPTIONAL",
    "DROP",
    "CONSTRAINT",
    "INDEX",
];

#[derive(Debug, thiserror::Error)]
pub enum CypherIdentifierError {
    #[error("identifier cannot be empty")]
    Empty,
    #[error("identifier '{0}' contains characters other than ASCII alphanumerics and underscores")]
    InvalidCharacters(String),
    #[error("identifier '{0}' cannot start with a digit")]
    StartsWithDigit(String),
    #[error("identifier '{0}' is a reserved Cypher keyword")]
    ReservedKeyword(String),
}

/// Validates that `s` is safe to interpolate directly into a Cypher query
/// as a label, relationship type, or property name. Cypher can only
/// parameterize property *values* -- never labels, relationship types, or
/// property names -- so anything derived from external/untrusted input
/// (a Jira custom field name, for example) that ends up in one of those
/// positions must pass this check first.
pub fn validate_cypher_identifier(s: &str) -> Result<(), CypherIdentifierError> {
    if s.is_empty() {
        return Err(CypherIdentifierError::Empty);
    }
    if s.chars().next().unwrap().is_ascii_digit() {
        return Err(CypherIdentifierError::StartsWithDigit(s.to_string()));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == 'Σ')
    {
        return Err(CypherIdentifierError::InvalidCharacters(s.to_string()));
    }
    if KEYWORD_BLACKLIST.contains(&s.to_ascii_uppercase().as_str()) {
        return Err(CypherIdentifierError::ReservedKeyword(s.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A name is taken exactly when it is made of the allowed characters, does not start with a digit, and is no
        /// keyword in any case, whatever it holds.
        #[test]
        fn a_name_is_taken_exactly_when_the_rule_says(name in "\\PC{0,10}|(?i)(match|merge|delete|set|drop)") {
            let plain = !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == 'Σ');
            let keyword = KEYWORD_BLACKLIST.iter().any(|k| k.eq_ignore_ascii_case(&name));
            prop_assert_eq!(validate_cypher_identifier(&name).is_ok(), plain && !keyword);
        }
    }
}
