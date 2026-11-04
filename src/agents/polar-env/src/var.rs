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

//! A variable, declared once.
//!
//! Three kinds, because they return three different things: [`Required`] gives the
//! value or an error, [`Optional`] gives `Some` or `None`, and [`Defaulted`] gives the
//! value, from its default when unset. A set value that does not parse is an error in
//! all three, never quietly the default: a typo must not run an agent on settings nobody
//! chose.

use crate::{Env, EnvError, Problem};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Required,
    Optional,
    Default,
}

/// Whether a variable may change while the agent runs.
///
/// `Static` (the default) is read once, when the agent starts: TLS paths, the broker
/// address, the capabilities, the health safety invariants. `Dynamic` may also be
/// overridden at runtime, by a scheduled configuration, and subscribers are told when it
/// changes. The code declares which, so what may change while an agent runs is decided by the
/// code and not by whoever publishes the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    Static,
    Dynamic,
}

/// What a declaration says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarDesc {
    pub name: &'static str,
    pub doc: &'static str,
    pub kind: Kind,
    /// The default, as text, for a [`Defaulted`] variable.
    pub default: Option<&'static str>,
    pub secret: bool,
    pub mutability: Mutability,
    /// For people: "text", "whole number", "whole number of seconds", ...
    pub type_name: &'static str,
    /// A value it could take, for a type that cannot make one up (see [`VarDesc::another_value`]).
    pub example: Option<&'static str>,
}

impl VarDesc {
    /// A value this variable can take other than `current`, which is what a test changes it to: a number goes up by
    /// one, a flag flips, a list gains an entry, and anything else takes the declaration's [`example`](Self::example).
    /// None when there is no example, or the example is what it already is.
    pub fn another_value(&self, current: Option<&str>) -> Option<String> {
        let current = current.or(self.default).map(str::trim);
        let example = self.example.filter(|example| Some(*example) != current);
        match self.type_name {
            "whole number" | "whole number of seconds" => {
                if let Some(example) = example {
                    return Some(example.to_string());
                }
                let number = current.map_or(Some(0), |text| text.parse::<u64>().ok())?;
                number.checked_add(1).map(|next| next.to_string())
            }
            "true or false" => Some(
                match current.map(parse_flag) {
                    Some(Ok(true)) => "false",
                    _ => "true",
                }
                .to_string(),
            ),
            "comma-separated list" => {
                let added = example.unwrap_or("another.invalid");
                Some(match current {
                    Some(text) if !text.is_empty() => format!("{text},{added}"),
                    _ => added.to_string(),
                })
            }
            _ => example.map(str::to_string),
        }
    }
}

/// Any declaration, whatever it parses to: what a [`crate::Section`] holds.
pub trait Described: Sync {
    fn desc(&self) -> VarDesc;

    /// Checks the variable against `env` without needing its value. A missing
    /// optional variable passes.
    fn validate(&self, env: &dyn Env) -> Result<(), EnvError>;
}

const HIDDEN: &str = "<hidden>";

struct Spec<T> {
    name: &'static str,
    doc: &'static str,
    type_name: &'static str,
    secret: bool,
    mutability: Mutability,
    example: Option<&'static str>,
    parse: fn(&str) -> Result<T, String>,
}

impl<T> Spec<T> {
    const fn new(
        name: &'static str,
        doc: &'static str,
        type_name: &'static str,
        parse: fn(&str) -> Result<T, String>,
    ) -> Self {
        Self {
            name,
            doc,
            type_name,
            secret: false,
            mutability: Mutability::Static,
            example: None,
            parse,
        }
    }

    const fn secret(&self) -> Self {
        Self {
            name: self.name,
            doc: self.doc,
            type_name: self.type_name,
            secret: true,
            mutability: self.mutability,
            example: self.example,
            parse: self.parse,
        }
    }

    const fn dynamic(&self) -> Self {
        Self {
            name: self.name,
            doc: self.doc,
            type_name: self.type_name,
            secret: self.secret,
            mutability: Mutability::Dynamic,
            example: self.example,
            parse: self.parse,
        }
    }

    const fn example(&self, example: &'static str) -> Self {
        Self {
            name: self.name,
            doc: self.doc,
            type_name: self.type_name,
            secret: self.secret,
            mutability: self.mutability,
            example: Some(example),
            parse: self.parse,
        }
    }

    /// The value, unless it is unset or blank.
    fn raw(&self, env: &dyn Env) -> Option<String> {
        env.var(self.name).filter(|v| !v.trim().is_empty())
    }

    fn parse_text(&self, text: &str) -> Result<T, EnvError> {
        (self.parse)(text).map_err(|reason| EnvError {
            name: self.name,
            doc: self.doc,
            problem: Problem::Malformed {
                shown: if self.secret {
                    HIDDEN.to_string()
                } else {
                    text.to_string()
                },
                reason,
            },
        })
    }

    fn missing(&self) -> EnvError {
        EnvError {
            name: self.name,
            doc: self.doc,
            problem: Problem::Missing,
        }
    }

    fn desc(&self, kind: Kind, default: Option<&'static str>) -> VarDesc {
        VarDesc {
            name: self.name,
            doc: self.doc,
            kind,
            default,
            secret: self.secret,
            mutability: self.mutability,
            type_name: self.type_name,
            example: self.example,
        }
    }
}

// -- parsers --------------------------------------------------------------------

fn parse_text(s: &str) -> Result<String, String> {
    Ok(s.to_string())
}

fn parse_number<T: FromStr>(s: &str) -> Result<T, String> {
    s.trim()
        .parse()
        .map_err(|_| "must be a whole number".to_string())
}

fn parse_seconds<T: FromStr>(s: &str) -> Result<T, String> {
    s.trim()
        .parse()
        .map_err(|_| "must be a whole number of seconds".to_string())
}

fn parse_flag(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err("must be true or false".to_string()),
    }
}

fn parse_list(s: &str) -> Result<Vec<String>, String> {
    Ok(s.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(String::from)
        .collect())
}

// -- the three kinds -------------------------------------------------------------

/// Must be set. [`read`](Self::read) gives the value.
pub struct Required<T>(Spec<T>);

/// May be absent. [`read`](Self::read) gives `Some(value)` or `None`.
pub struct Optional<T>(Spec<T>);

/// Has a default, used when unset. [`read`](Self::read) gives the value.
pub struct Defaulted<T> {
    spec: Spec<T>,
    default: &'static str,
}

impl<T> Required<T> {
    /// The variable's name, usable in a constant.
    pub const fn name(&self) -> &'static str {
        self.0.name
    }

    pub const fn new(
        name: &'static str,
        doc: &'static str,
        type_name: &'static str,
        parse: fn(&str) -> Result<T, String>,
    ) -> Self {
        Self(Spec::new(name, doc, type_name, parse))
    }

    /// Never shown in an error or a description.
    pub const fn secret(self) -> Self {
        Self(self.0.secret())
    }

    /// May be overridden while the agent runs. See [`Mutability`].
    pub const fn dynamic(self) -> Self {
        Self(self.0.dynamic())
    }

    /// A value it could take, for a Dynamic variable whose type cannot make one up.
    pub const fn example(self, example: &'static str) -> Self {
        Self(self.0.example(example))
    }

    pub fn read(&self, env: &dyn Env) -> Result<T, EnvError> {
        match self.0.raw(env) {
            Some(text) => self.0.parse_text(&text),
            None => Err(self.0.missing()),
        }
    }
}

impl<T> Optional<T> {
    /// The variable's name, usable in a constant.
    pub const fn name(&self) -> &'static str {
        self.0.name
    }

    pub const fn new(
        name: &'static str,
        doc: &'static str,
        type_name: &'static str,
        parse: fn(&str) -> Result<T, String>,
    ) -> Self {
        Self(Spec::new(name, doc, type_name, parse))
    }

    /// Never shown in an error or a description.
    pub const fn secret(self) -> Self {
        Self(self.0.secret())
    }

    /// May be overridden while the agent runs. See [`Mutability`].
    pub const fn dynamic(self) -> Self {
        Self(self.0.dynamic())
    }

    /// A value it could take, for a Dynamic variable whose type cannot make one up.
    pub const fn example(self, example: &'static str) -> Self {
        Self(self.0.example(example))
    }

    pub fn read(&self, env: &dyn Env) -> Result<Option<T>, EnvError> {
        match self.0.raw(env) {
            Some(text) => self.0.parse_text(&text).map(Some),
            None => Ok(None),
        }
    }
}

impl<T> Defaulted<T> {
    /// The variable's name, usable in a constant.
    pub const fn name(&self) -> &'static str {
        self.spec.name
    }

    pub const fn new(
        name: &'static str,
        doc: &'static str,
        type_name: &'static str,
        parse: fn(&str) -> Result<T, String>,
        default: &'static str,
    ) -> Self {
        Self {
            spec: Spec::new(name, doc, type_name, parse),
            default,
        }
    }

    /// Never shown in an error or a description.
    pub const fn secret(self) -> Self {
        Self {
            spec: self.spec.secret(),
            default: self.default,
        }
    }

    /// May be overridden while the agent runs. See [`Mutability`].
    pub const fn dynamic(self) -> Self {
        Self {
            spec: self.spec.dynamic(),
            default: self.default,
        }
    }

    /// A value it could take, for a Dynamic variable whose type cannot make one up.
    pub const fn example(self, example: &'static str) -> Self {
        Self {
            spec: self.spec.example(example),
            default: self.default,
        }
    }

    pub fn read(&self, env: &dyn Env) -> Result<T, EnvError> {
        let text = self
            .spec
            .raw(env)
            .unwrap_or_else(|| self.default.to_string());
        self.spec.parse_text(&text)
    }
}

/// A declaration that can be read, whatever it reads to.
///
/// [`Config::read`](crate::Config::read) takes any of the three kinds through this, and
/// checks the variable is declared by a registered section before reading it.
pub trait Readable: Described {
    type Out;

    fn name(&self) -> &'static str;

    fn read_from(&self, env: &dyn Env) -> Result<Self::Out, EnvError>;
}

impl<T: Send + Sync> Readable for Required<T> {
    type Out = T;

    fn name(&self) -> &'static str {
        self.0.name
    }

    fn read_from(&self, env: &dyn Env) -> Result<T, EnvError> {
        self.read(env)
    }
}

impl<T: Send + Sync> Readable for Optional<T> {
    type Out = Option<T>;

    fn name(&self) -> &'static str {
        self.0.name
    }

    fn read_from(&self, env: &dyn Env) -> Result<Option<T>, EnvError> {
        self.read(env)
    }
}

impl<T: Send + Sync> Readable for Defaulted<T> {
    type Out = T;

    fn name(&self) -> &'static str {
        self.spec.name
    }

    fn read_from(&self, env: &dyn Env) -> Result<T, EnvError> {
        self.read(env)
    }
}

/// The constructors for each type a variable can parse to.
macro_rules! constructors {
    ($Kind:ident, ($($extra:ident),*)) => {
        impl $Kind<String> {
            pub const fn text(name: &'static str, doc: &'static str $(, $extra: &'static str)*) -> Self {
                Self::new(name, doc, "text", parse_text $(, $extra)*)
            }
        }

        impl<T: FromStr> $Kind<T> {
            pub const fn number(name: &'static str, doc: &'static str $(, $extra: &'static str)*) -> Self {
                Self::new(name, doc, "whole number", parse_number::<T> $(, $extra)*)
            }

            pub const fn seconds(name: &'static str, doc: &'static str $(, $extra: &'static str)*) -> Self {
                Self::new(name, doc, "whole number of seconds", parse_seconds::<T> $(, $extra)*)
            }
        }

        impl $Kind<bool> {
            pub const fn flag(name: &'static str, doc: &'static str $(, $extra: &'static str)*) -> Self {
                Self::new(name, doc, "true or false", parse_flag $(, $extra)*)
            }
        }

        impl $Kind<Vec<String>> {
            pub const fn list(name: &'static str, doc: &'static str $(, $extra: &'static str)*) -> Self {
                Self::new(name, doc, "comma-separated list", parse_list $(, $extra)*)
            }
        }
    };
}

constructors!(Required, ());
constructors!(Optional, ());
constructors!(Defaulted, (default));

impl<T: Send + Sync> Described for Required<T> {
    fn desc(&self) -> VarDesc {
        self.0.desc(Kind::Required, None)
    }

    fn validate(&self, env: &dyn Env) -> Result<(), EnvError> {
        self.read(env).map(|_| ())
    }
}

impl<T: Send + Sync> Described for Optional<T> {
    fn desc(&self) -> VarDesc {
        self.0.desc(Kind::Optional, None)
    }

    fn validate(&self, env: &dyn Env) -> Result<(), EnvError> {
        self.read(env).map(|_| ())
    }
}

impl<T: Send + Sync> Described for Defaulted<T> {
    fn desc(&self) -> VarDesc {
        self.spec.desc(Kind::Default, Some(self.default))
    }

    fn validate(&self, env: &dyn Env) -> Result<(), EnvError> {
        self.read(env).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Env, EnvError, Problem};
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // -- required ---------------------------------------------------------------

    #[test]
    fn a_missing_required_variable_names_itself_and_its_purpose() {
        let v = Required::<String>::text("TLS_CA_CERT", "the CA certificate");
        let err = v.read(&env(&[])).unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS_CA_CERT is not set (the CA certificate)"
        );
        assert_eq!(err.problem, Problem::Missing);
    }

    #[test]
    fn a_blank_value_counts_as_unset() {
        let v = Required::<String>::text("X", "d");
        for blank in ["", "  ", "\t"] {
            assert_eq!(
                v.read(&env(&[("X", blank)])).unwrap_err().problem,
                Problem::Missing
            );
        }
    }

    #[test]
    fn text_is_returned_exactly_as_given() {
        // A password with spaces at the ends is a password.
        let v = Required::<String>::text("X", "d");
        assert_eq!(v.read(&env(&[("X", "  a b ")])).unwrap(), "  a b ");
    }

    #[test]
    fn a_number_is_read_with_whitespace_trimmed() {
        let v = Required::<u64>::number("N", "d");
        assert_eq!(v.read(&env(&[("N", " 42 ")])).unwrap(), 42);
    }

    #[test]
    fn a_malformed_number_says_what_was_wrong() {
        let v = Required::<u64>::number("N", "the count");
        let err = v.read(&env(&[("N", "soon")])).unwrap_err();
        assert_eq!(
            err.to_string(),
            "N must be a whole number, got 'soon' (the count)"
        );
    }

    #[test]
    fn seconds_say_so() {
        let v = Required::<u64>::seconds("T", "the timeout");
        let err = v.read(&env(&[("T", "30s")])).unwrap_err();
        assert!(
            err.to_string()
                .contains("must be a whole number of seconds"),
            "{err}"
        );
        assert_eq!(v.read(&env(&[("T", "30")])).unwrap(), 30);
    }

    #[test]
    fn signed_and_unsigned_numbers_differ_on_negatives() {
        assert!(
            Required::<u64>::number("N", "d")
                .read(&env(&[("N", "-3")]))
                .is_err()
        );
        assert_eq!(
            Required::<i64>::number("N", "d")
                .read(&env(&[("N", "-3")]))
                .unwrap(),
            -3
        );
    }

    #[test]
    fn flags_accept_the_usual_spellings() {
        let v = Required::<bool>::flag("F", "d");
        for yes in ["true", "TRUE", "1", "yes", "Yes"] {
            assert!(v.read(&env(&[("F", yes)])).unwrap(), "{yes}");
        }
        for no in ["false", "FALSE", "0", "no", "No"] {
            assert!(!v.read(&env(&[("F", no)])).unwrap(), "{no}");
        }
        let err = v.read(&env(&[("F", "maybe")])).unwrap_err();
        assert!(err.to_string().contains("must be true or false"), "{err}");
    }

    #[test]
    fn a_list_is_split_on_commas_trimmed_and_blanks_dropped() {
        let v = Required::<Vec<String>>::list("L", "d");
        assert_eq!(
            v.read(&env(&[("L", " a, b ,,c ,")])).unwrap(),
            ["a", "b", "c"]
        );
    }

    // -- optional ------------------------------------------------------------------

    #[test]
    fn an_optional_variable_may_be_absent() {
        let v = Optional::<String>::text("O", "d");
        assert_eq!(v.read(&env(&[])).unwrap(), None);
        assert_eq!(v.read(&env(&[("O", "  ")])).unwrap(), None);
        assert_eq!(v.read(&env(&[("O", "x")])).unwrap(), Some("x".to_string()));
    }

    #[test]
    fn an_optional_variable_that_is_set_must_still_parse() {
        let v = Optional::<u64>::number("O", "d");
        assert!(v.read(&env(&[("O", "x")])).is_err());
        assert_eq!(v.read(&env(&[("O", "7")])).unwrap(), Some(7));
    }

    // -- defaulted -----------------------------------------------------------------

    #[test]
    fn a_defaulted_variable_uses_its_default_when_unset_or_blank() {
        let v = Defaulted::<u64>::seconds("T", "d", "30");
        assert_eq!(v.read(&env(&[])).unwrap(), 30);
        assert_eq!(v.read(&env(&[("T", " ")])).unwrap(), 30);
        assert_eq!(v.read(&env(&[("T", "5")])).unwrap(), 5);
    }

    #[test]
    fn a_set_value_that_does_not_parse_is_an_error_not_the_default() {
        // A typo must not quietly run the agent on settings nobody chose.
        let v = Defaulted::<u64>::seconds("T", "d", "30");
        assert!(v.read(&env(&[("T", "soon")])).is_err());
    }

    #[test]
    fn a_default_that_does_not_parse_is_caught() {
        let v = Defaulted::<u64>::number("T", "d", "thirty");
        let err = v.read(&env(&[])).unwrap_err();
        assert!(err.to_string().contains("thirty"), "{err}");
    }

    // -- secrets -------------------------------------------------------------------

    #[test]
    fn a_secret_is_never_shown_in_an_error() {
        let v = Required::<u64>::number("PIN", "the pin").secret();
        let err = v.read(&env(&[("PIN", "hunter2")])).unwrap_err();
        let shown = err.to_string();
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("<hidden>"), "{shown}");
        assert!(shown.contains("PIN"), "{shown}");
    }

    // -- description and validation ----------------------------------------------

    #[test]
    fn each_kind_describes_itself() {
        let r = Required::<String>::text("R", "required one").secret();
        let o = Optional::<u64>::number("O", "optional one");
        let d = Defaulted::<u64>::seconds("D", "defaulted one", "30");

        let rd = r.desc();
        assert_eq!(
            (rd.name, rd.doc, rd.kind, rd.secret),
            ("R", "required one", Kind::Required, true)
        );
        assert_eq!(rd.default, None);
        assert_eq!(rd.type_name, "text");

        let od = o.desc();
        assert_eq!(
            (od.kind, od.secret, od.default),
            (Kind::Optional, false, None)
        );
        assert_eq!(od.type_name, "whole number");

        let dd = d.desc();
        assert_eq!((dd.kind, dd.default), (Kind::Default, Some("30")));
        assert_eq!(dd.type_name, "whole number of seconds");
    }

    #[test]
    fn validate_checks_without_needing_the_value() {
        let v: &dyn Described = &Required::<u64>::number("N", "d");
        assert!(v.validate(&env(&[("N", "5")])).is_ok());
        assert_eq!(v.validate(&env(&[])).unwrap_err().problem, Problem::Missing);
        assert!(matches!(
            v.validate(&env(&[("N", "x")])).unwrap_err().problem,
            Problem::Malformed { .. }
        ));
    }

    #[test]
    fn validating_an_optional_variable_accepts_absence() {
        let v: &dyn Described = &Optional::<u64>::number("N", "d");
        assert!(v.validate(&env(&[])).is_ok());
    }

    #[test]
    fn declarations_can_be_statics() {
        static A: Required<String> = Required::text("A", "a");
        static B: Defaulted<u64> = Defaulted::number("B", "b", "1");
        static ALL: &[&dyn Described] = &[&A, &B];
        assert_eq!(
            ALL.iter().map(|v| v.desc().name).collect::<Vec<_>>(),
            ["A", "B"]
        );
    }

    #[test]
    fn a_declaration_knows_its_name_at_compile_time() {
        // So a constant for the name can be derived from the declaration, and the name
        // is written once.
        const R: Required<String> = Required::text("A_NAME", "d");
        const O: Optional<u64> = Optional::number("B_NAME", "d");
        const D: Defaulted<u64> = Defaulted::number("C_NAME", "d", "1");
        const NAMES: [&str; 3] = [R.name(), O.name(), D.name()];
        assert_eq!(NAMES, ["A_NAME", "B_NAME", "C_NAME"]);
    }

    // -- mutability --------------------------------------------------------------

    #[test]
    fn a_variable_is_static_unless_it_says_it_may_change_at_runtime() {
        assert_eq!(
            Required::<String>::text("A", "d").desc().mutability,
            Mutability::Static
        );
        assert_eq!(
            Optional::<u64>::number("B", "d").desc().mutability,
            Mutability::Static
        );
        assert_eq!(
            Defaulted::<u64>::number("C", "d", "1").desc().mutability,
            Mutability::Static
        );
    }

    #[test]
    fn any_kind_can_be_declared_dynamic() {
        assert_eq!(
            Required::<String>::text("A", "d")
                .dynamic()
                .desc()
                .mutability,
            Mutability::Dynamic
        );
        assert_eq!(
            Optional::<u64>::number("B", "d")
                .dynamic()
                .desc()
                .mutability,
            Mutability::Dynamic
        );
        assert_eq!(
            Defaulted::<u64>::number("C", "d", "1")
                .dynamic()
                .desc()
                .mutability,
            Mutability::Dynamic
        );
    }

    #[test]
    fn dynamic_and_secret_combine_in_either_order() {
        let a = Optional::<String>::text("A", "d").secret().dynamic().desc();
        let b = Optional::<String>::text("A", "d").dynamic().secret().desc();
        assert!(a.secret && b.secret);
        assert_eq!(
            (a.mutability, b.mutability),
            (Mutability::Dynamic, Mutability::Dynamic)
        );
    }

    #[test]
    fn a_variable_can_be_read_through_the_common_trait() {
        fn name_of<R: Readable>(v: &R) -> &'static str {
            v.name()
        }
        assert_eq!(name_of(&Required::<String>::text("R", "d")), "R");
        let d = Defaulted::<u64>::number("D", "d", "7");
        assert_eq!(Readable::read_from(&d, &env(&[])).unwrap(), 7);
        let o = Optional::<u64>::number("O", "d");
        assert_eq!(Readable::read_from(&o, &env(&[])).unwrap(), None);
    }

    // -- another value ----------------------------------------------------------

    static SOME_NUMBER: Defaulted<u64> = Defaulted::number("SOME_NUMBER", "a number", "7");
    static SOME_SECONDS: Optional<u64> = Optional::seconds("SOME_SECONDS", "some seconds");
    static SOME_FLAG: Defaulted<bool> = Defaulted::flag("SOME_FLAG", "a flag", "false");
    static SOME_LIST: Defaulted<Vec<String>> = Defaulted::list("SOME_LIST", "a list", "");
    static BARE_TEXT: Optional<String> = Optional::text("BARE_TEXT", "text");
    static SOME_TEXT: Required<String> =
        Required::text("SOME_TEXT", "text").example("https://site.invalid");

    #[test]
    fn a_type_that_can_make_up_another_value_does_and_text_needs_an_example() {
        assert_eq!(SOME_NUMBER.desc().another_value(None).as_deref(), Some("8"));
        assert_eq!(
            SOME_SECONDS.desc().another_value(None).as_deref(),
            Some("1")
        );
        assert_eq!(
            SOME_FLAG.desc().another_value(None).as_deref(),
            Some("true")
        );
        assert_eq!(
            SOME_FLAG.desc().another_value(Some("yes")).as_deref(),
            Some("false")
        );
        assert_eq!(
            SOME_LIST.desc().another_value(Some("a,b")).as_deref(),
            Some("a,b,another.invalid")
        );
        assert_eq!(BARE_TEXT.desc().another_value(Some("x")), None);
        assert_eq!(
            SOME_TEXT.desc().another_value(Some("x")).as_deref(),
            Some("https://site.invalid")
        );
        // What it is already is no other value.
        assert_eq!(
            SOME_TEXT.desc().another_value(Some("https://site.invalid")),
            None
        );
    }

    proptest::proptest! {
        /// Another value is another value, and the variable takes it.
        #[test]
        fn another_value_differs_and_parses(number in 0u64..u64::MAX, flag: bool, items in proptest::collection::vec("[a-z]{1,5}", 0..4)) {
            let text = number.to_string();
            let next = SOME_NUMBER.desc().another_value(Some(&text)).unwrap();
            proptest::prop_assert_ne!(&next, &text);
            proptest::prop_assert_eq!(SOME_NUMBER.read(&env(&[("SOME_NUMBER", &next)])), Ok(number + 1));

            let text = flag.to_string();
            let next = SOME_FLAG.desc().another_value(Some(&text)).unwrap();
            proptest::prop_assert_eq!(SOME_FLAG.read(&env(&[("SOME_FLAG", &next)])), Ok(!flag));

            let text = items.join(",");
            let next = SOME_LIST.desc().another_value(Some(&text)).unwrap();
            let read = SOME_LIST.read(&env(&[("SOME_LIST", &next)])).unwrap();
            proptest::prop_assert_eq!(read.len(), items.len() + 1);
            proptest::prop_assert_eq!(&read[..items.len()], &items[..]);
        }
    }

    // keeps the imports honest
    #[allow(dead_code)]
    fn _types(_: &dyn Env, _: EnvError) {}
}
