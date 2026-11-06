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

//! How a source is paged, and where its next page is. The observer reads a page only as far as its paging needs: the
//! `Link` header, the address at a JSON pointer, or how many items a page holds. Each page is published as it is read
//! (docs/architecture/http-observers.md, "Evidence", bite 7). A next page is on the source's own host: a host does not
//! send the observer, or a credential, anywhere else.

use serde_json::Value;

/// Pages read in one read of a source when the section does not say.
pub const DEFAULT_MAX_PAGES: u32 = 100;
/// The most a section may say.
pub const MAX_PAGES: u32 = 1000;
/// Longest query parameter, and longest JSON pointer.
pub const MAX_PARAM: usize = 64;
pub const MAX_POINTER: usize = 256;

/// Where the next page is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Style {
    /// The `Link` header's `rel="next"`, as GitLab and GitHub page.
    Link,
    /// The address at a JSON pointer in the page, as Jira's `nextPage`; absent, null or empty on the last.
    Cursor { next: String },
    /// A query parameter, absent on the first page, set to how many items were read so far, as Jira's `startAt`; the items
    /// are the list at a JSON pointer, and a page with none is the last.
    Offset { param: String, items: String },
    /// A GraphQL connection at a JSON pointer, as GitLab's: while its `pageInfo.hasNextPage`, the same query again with
    /// `$after` its `endCursor`. Only for a source read as GraphQL.
    GraphQl { connection: String },
}

/// Where the next page is: an address to GET, or a cursor to ask the same query after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    At(String),
    After(String),
}

/// How a source is paged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paging {
    pub style: Style,
    /// Pages read in one read of the source; a next page beyond them is a problem for the source.
    pub max_pages: u32,
}

/// What a page is asked with: where, with which credential, how the source is paged, and, for a GraphQL source, its
/// query and the cursor this page comes after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub url: String,
    pub credential: Option<String>,
    pub paging: Option<Style>,
    pub query: Option<String>,
    pub after: Option<String>,
    /// A follow-up's variables, from its item, besides the cursor.
    pub variables: serde_json::Map<String, serde_json::Value>,
    /// For a page whose items are followed: where they are, and the variables taken from each.
    pub pick: Option<Pick>,
}

/// Where a page's items are, and each variable a follow-up takes from one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    pub items: String,
    pub variables: Vec<crate::graphql::Variable>,
}

impl PageRequest {
    /// A page read by GET.
    pub fn new(url: String, credential: Option<String>, paging: Option<Style>) -> Self {
        Self {
            url,
            credential,
            paging,
            query: None,
            after: None,
            variables: serde_json::Map::new(),
            pick: None,
        }
    }

    /// The page is `query`, POSTed, after the cursor `after`, none on the first page.
    pub fn graphql(mut self, query: impl Into<String>, after: Option<String>) -> Self {
        self.query = Some(query.into());
        self.after = after;
        self
    }
}

/// A page as it was read: what is published, and the next page's address when there is one to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub body: Vec<u8>,
    pub next: Option<Next>,
    /// Each item the page holds whose follow-up can be asked: its variables, for a source that follows its items.
    pub items: Vec<serde_json::Map<String, Value>>,
    /// The items it holds that lack a variable, and so cannot be followed.
    pub unfollowable: usize,
}

/// A source's `paging`, or every problem with it, each naming its field.
pub fn parse(value: &Value) -> Result<Paging, Vec<String>> {
    let Some(object) = value.as_object() else {
        return Err(vec!["`paging` must be an object".to_string()]);
    };
    // A field a signed list writes as null, because another entry has it, is one left out.
    let given = |key: &str| object.get(key).filter(|v| !v.is_null());
    let mut problems: Vec<String> = object
        .keys()
        .filter(|k| {
            !["style", "next", "param", "items", "connection", "max_pages"].contains(&k.as_str())
        })
        .map(|k| format!("`paging`: `{k}` is not a field"))
        .collect();
    let text = |key: &str,
                problems: &mut Vec<String>,
                check: fn(&str) -> bool,
                what: &str|
     -> Option<String> {
        match given(key) {
            Some(Value::String(t)) if check(t) => Some(t.clone()),
            _ => {
                problems.push(format!("`paging`: `{key}` must be {what}"));
                None
            }
        }
    };
    let style = match given("style").and_then(Value::as_str) {
        Some("link") => Some(Style::Link),
        Some("cursor") => text(
            "next",
            &mut problems,
            is_pointer,
            "a JSON pointer: empty, or starting with `/`",
        )
        .map(|next| Style::Cursor { next }),
        Some("offset") => {
            let param = text(
                "param",
                &mut problems,
                is_param,
                "a query parameter's name: letters, digits, `_`, `-` and `.`",
            );
            let items = text(
                "items",
                &mut problems,
                is_pointer,
                "a JSON pointer: empty, or starting with `/`",
            );
            param
                .zip(items)
                .map(|(param, items)| Style::Offset { param, items })
        }
        Some("graphql") => text(
            "connection",
            &mut problems,
            |t| t.starts_with('/') && is_pointer(t),
            "a JSON pointer to the connection, starting with `/`",
        )
        .map(|connection| Style::GraphQl { connection }),
        _ => {
            problems.push(
                "`paging`: `style` must be `link`, `cursor`, `offset` or `graphql`".to_string(),
            );
            None
        }
    };
    // A field another style takes is a mistake here, not something to ignore.
    let takes: &[&str] = match &style {
        Some(Style::Link) => &[],
        Some(Style::Cursor { .. }) => &["next"],
        Some(Style::Offset { .. }) => &["param", "items"],
        Some(Style::GraphQl { .. }) => &["connection"],
        None => &["next", "param", "items", "connection"],
    };
    for key in ["next", "param", "items", "connection"] {
        if !takes.contains(&key) && given(key).is_some() {
            problems.push(format!("`paging`: `{key}` is not taken by this style"));
        }
    }
    let max_pages = match given("max_pages") {
        None => Some(DEFAULT_MAX_PAGES),
        Some(v) => match v.as_u64() {
            Some(n) if (1..=u64::from(MAX_PAGES)).contains(&n) => Some(n as u32),
            _ => {
                problems.push(format!(
                    "`paging`: `max_pages` must be from 1 to {MAX_PAGES}"
                ));
                None
            }
        },
    };
    match (style, max_pages) {
        (Some(style), Some(max_pages)) if problems.is_empty() => Ok(Paging { style, max_pages }),
        _ => Err(problems),
    }
}

pub(crate) fn is_pointer(t: &str) -> bool {
    t.len() <= MAX_POINTER && (t.is_empty() || t.starts_with('/'))
}

fn is_param(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= MAX_PARAM
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Where the next page is, given the page at `current`, asked after the cursor `after` for a GraphQL source, and what came
/// back with it: `link`, each `Link` header's value; `body`, the page. None on the last page.
pub fn following(
    style: &Style,
    current: &str,
    after: Option<&str>,
    link: &[String],
    body: &[u8],
) -> Result<Option<Next>, String> {
    let Style::GraphQl { connection } = style else {
        return next(style, current, link, body).map(|at| at.map(Next::At));
    };
    let page = object(body)?;
    let Some(info) = page.pointer(&format!("{connection}/pageInfo")) else {
        return Err(format!("the page has no `pageInfo` at `{connection}`"));
    };
    match info.get("hasNextPage") {
        Some(Value::Bool(false)) => Ok(None),
        Some(Value::Bool(true)) => match info.get("endCursor") {
            Some(Value::String(end)) if !end.is_empty() => {
                if Some(end.as_str()) == after {
                    Err("the next page is the page itself: its `endCursor` is the cursor it was asked after".to_string())
                } else {
                    Ok(Some(Next::After(end.clone())))
                }
            }
            _ => Err(format!(
                "`{connection}/pageInfo` says there is a next page and has no `endCursor`"
            )),
        },
        _ => Err(format!(
            "`{connection}/pageInfo/hasNextPage` is not true or false"
        )),
    }
}

/// The next address of a page paged by address: [`following`] for every style but GraphQL's.
pub fn next(
    style: &Style,
    current: &str,
    link: &[String],
    body: &[u8],
) -> Result<Option<String>, String> {
    let at =
        url::Url::parse(current).map_err(|_| "the page's address cannot be read".to_string())?;
    let named = match style {
        Style::Link => link.iter().find_map(|value| next_in_link(value)),
        Style::GraphQl { .. } => {
            return Err("a GraphQL page's next is a cursor, not an address".to_string());
        }
        Style::Cursor { next } => match object(body)?.pointer(next) {
            None | Some(Value::Null) => None,
            Some(Value::String(t)) if t.is_empty() => None,
            Some(Value::String(t)) => Some(t.clone()),
            Some(_) => return Err(format!("what is at `{next}` is not an address")),
        },
        Style::Offset { param, items } => {
            let count = match document(body)?.pointer(items) {
                Some(Value::Array(list)) => list.len() as u64,
                _ => return Err(format!("what is at `{items}` is not a list")),
            };
            if count == 0 {
                return Ok(None);
            }
            let start = match at.query_pairs().find(|(k, _)| k == param.as_str()) {
                None => 0,
                Some((_, v)) => v
                    .parse::<u64>()
                    .map_err(|_| format!("the page's `{param}` is not a whole number"))?,
            };
            let kept: Vec<(String, String)> = at
                .query_pairs()
                .filter(|(k, _)| k != param.as_str())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            let mut following = at.clone();
            following
                .query_pairs_mut()
                .clear()
                .extend_pairs(kept)
                .append_pair(param, &(start + count).to_string());
            return Ok(Some(following.to_string()));
        }
    };
    let Some(named) = named else {
        return Ok(None);
    };
    let following = at
        .join(named.trim())
        .map_err(|_| "the next page's address cannot be read".to_string())?;
    if following.origin() != at.origin() {
        return Err("the next page is on another host, scheme or port than the source".to_string());
    }
    if following == at {
        return Err("the next page is the page itself".to_string());
    }
    Ok(Some(following.to_string()))
}

fn document(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(body).map_err(|_| "the page is not JSON".to_string())
}

/// A page a cursor is read from: an object, since a cursor is one of its fields.
fn object(body: &[u8]) -> Result<Value, String> {
    let page = document(body)?;
    if page.is_object() {
        Ok(page)
    } else {
        Err("the page is not a JSON object, so it holds no cursor".to_string())
    }
}

/// The target of the `rel="next"` link in one `Link` header value (RFC 8288), if it has one.
fn next_in_link(value: &str) -> Option<String> {
    let mut rest = value;
    loop {
        let open = rest.find('<')?;
        let close = open + rest[open..].find('>')?;
        let target = &rest[open + 1..close];
        let after = &rest[close + 1..];
        // Its parameters run to the next link, which begins with `<`.
        let params = &after[..after.find('<').unwrap_or(after.len())];
        let is_next = params.split(';').any(|param| {
            let Some((key, val)) = param.split_once('=') else {
                return false;
            };
            key.trim().eq_ignore_ascii_case("rel")
                && val
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .trim_matches('"')
                    .split_ascii_whitespace()
                    .any(|rel| rel.eq_ignore_ascii_case("next"))
        });
        if is_next {
            return Some(target.to_string());
        }
        rest = after;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn problems_of(value: Value) -> Vec<String> {
        parse(&value).unwrap_err()
    }

    #[test]
    fn each_style_is_read_as_it_says_and_a_bound_left_out_is_the_default() {
        assert_eq!(
            parse(&json!({ "style": "link" })).unwrap(),
            Paging {
                style: Style::Link,
                max_pages: DEFAULT_MAX_PAGES
            }
        );
        assert_eq!(
            parse(&json!({ "style": "cursor", "next": "/nextPage", "max_pages": 7 })).unwrap(),
            Paging {
                style: Style::Cursor {
                    next: "/nextPage".into()
                },
                max_pages: 7
            }
        );
        assert_eq!(
            parse(&json!({ "style": "offset", "param": "startAt", "items": "", "max_pages": MAX_PAGES })).unwrap(),
            Paging { style: Style::Offset { param: "startAt".into(), items: "".into() }, max_pages: MAX_PAGES }
        );
        // As a signed list writes a field another entry has and this one leaves out.
        assert_eq!(
            parse(&json!({ "style": "link", "next": null, "param": null, "items": null, "max_pages": null })).unwrap(),
            Paging { style: Style::Link, max_pages: DEFAULT_MAX_PAGES }
        );
    }

    #[test]
    fn a_paging_that_cannot_work_is_refused_naming_its_field() {
        let cases: &[(Value, &str)] = &[
            (json!("link"), "object"),
            (json!({}), "`style`"),
            (json!({ "style": "pages" }), "`style`"),
            (json!({ "style": "cursor" }), "`next`"),
            (json!({ "style": "cursor", "next": "nextPage" }), "`next`"),
            (json!({ "style": "offset", "items": "/values" }), "`param`"),
            (
                json!({ "style": "offset", "param": "start at", "items": "/values" }),
                "`param`",
            ),
            (json!({ "style": "offset", "param": "startAt" }), "`items`"),
            (json!({ "style": "link", "next": "/nextPage" }), "`next`"),
            (json!({ "style": "link", "param": "page" }), "`param`"),
            (json!({ "style": "link", "max_pages": 0 }), "`max_pages`"),
            (
                json!({ "style": "link", "max_pages": MAX_PAGES + 1 }),
                "`max_pages`",
            ),
            (json!({ "style": "link", "after": "x" }), "`after`"),
        ];
        for (value, field) in cases {
            let problems = problems_of(value.clone());
            assert!(
                problems.iter().any(|p| p.contains(field)),
                "{value}: {problems:?}"
            );
        }
    }

    #[test]
    fn a_link_header_s_next_is_the_next_page_and_none_is_the_last() {
        let at = "https://gitlab.example/api/v4/projects?page=1";
        let link = vec![
            r#"<https://gitlab.example/api/v4/projects?page=2>; rel="next", <https://gitlab.example/api/v4/projects?page=9>; rel="last""#
                .to_string(),
        ];
        assert_eq!(
            next(&Style::Link, at, &link, b"[]").unwrap().as_deref(),
            Some("https://gitlab.example/api/v4/projects?page=2")
        );
        let last =
            vec![r#"<https://gitlab.example/api/v4/projects?page=1>; rel="first""#.to_string()];
        assert_eq!(next(&Style::Link, at, &last, b"[]").unwrap(), None);
        assert_eq!(next(&Style::Link, at, &[], b"[]").unwrap(), None);
        // Relative, unquoted, among other relations, and in a header of its own.
        let split = vec![
            "</api/v4/projects?page=1>; rel=prev".to_string(),
            "</api/v4/projects?page=3>; rel=\"next last\"".to_string(),
        ];
        assert_eq!(
            next(&Style::Link, at, &split, b"[]").unwrap().as_deref(),
            Some("https://gitlab.example/api/v4/projects?page=3")
        );
    }

    #[test]
    fn a_cursor_is_the_address_at_its_pointer_and_absent_null_or_empty_is_the_last() {
        let style = Style::Cursor {
            next: "/nextPage".into(),
        };
        let at = "https://jira.example/rest/api/3/project/search";
        let page = br#"{"values": [], "nextPage": "https://jira.example/rest/api/3/project/search?startAt=50"}"#;
        assert_eq!(
            next(&style, at, &[], page).unwrap().as_deref(),
            Some("https://jira.example/rest/api/3/project/search?startAt=50")
        );
        for last in [
            &br#"{"values": [], "isLast": true}"#[..],
            br#"{"nextPage": null}"#,
            br#"{"nextPage": ""}"#,
        ] {
            assert_eq!(next(&style, at, &[], last).unwrap(), None);
        }
        for bad in [&br#"{"nextPage": 50}"#[..], b"not json", br#"["a list"]"#] {
            assert!(next(&style, at, &[], bad).is_err());
        }
    }

    #[test]
    fn an_offset_advances_by_the_items_a_page_holds_and_an_empty_page_is_the_last() {
        let style = Style::Offset {
            param: "startAt".into(),
            items: "".into(),
        };
        let at = "https://jira.example/rest/api/3/users/search?maxResults=2";
        assert_eq!(
            next(&style, at, &[], br#"[{"a": 1}, {"a": 2}]"#)
                .unwrap()
                .as_deref(),
            Some("https://jira.example/rest/api/3/users/search?maxResults=2&startAt=2")
        );
        assert_eq!(
            next(
                &style,
                "https://jira.example/rest/api/3/users/search?maxResults=2&startAt=2",
                &[],
                br#"[{"a": 3}]"#
            )
            .unwrap()
            .as_deref(),
            Some("https://jira.example/rest/api/3/users/search?maxResults=2&startAt=3")
        );
        assert_eq!(next(&style, at, &[], b"[]").unwrap(), None);
        let inner = Style::Offset {
            param: "startAt".into(),
            items: "/values".into(),
        };
        assert!(next(&inner, at, &[], br#"{"values": {}}"#).is_err());
        assert!(next(&inner, at, &[], br#"{"other": []}"#).is_err());
        assert!(next(&style, &format!("{at}&startAt=x"), &[], b"[1]").is_err());
    }

    #[test]
    fn a_next_page_on_another_host_or_that_is_the_page_itself_is_refused() {
        let at = "https://jira.example/rest/api/3/project/search";
        let cursor = Style::Cursor {
            next: "/nextPage".into(),
        };
        for elsewhere in [
            "https://attacker.example/rest/api/3/project/search?startAt=50",
            "http://jira.example/rest/api/3/project/search?startAt=50",
            "https://jira.example:8443/rest/api/3/project/search?startAt=50",
        ] {
            let page = json!({ "nextPage": elsewhere }).to_string();
            let refused = next(&cursor, at, &[], page.as_bytes()).unwrap_err();
            assert!(refused.contains("host"), "{elsewhere}: {refused}");
        }
        let itself = json!({ "nextPage": at }).to_string();
        assert!(next(&cursor, at, &[], itself.as_bytes()).is_err());
        let link = vec!["<https://other.example/x>; rel=\"next\"".to_string()];
        assert!(next(&Style::Link, at, &link, b"").is_err());
    }

    #[test]
    fn a_graphql_paging_names_where_its_connection_is() {
        assert_eq!(
            parse(&json!({ "style": "graphql", "connection": "/data/projects", "max_pages": 5 }))
                .unwrap(),
            Paging {
                style: Style::GraphQl {
                    connection: "/data/projects".into()
                },
                max_pages: 5
            }
        );
        for (value, field) in [
            (json!({ "style": "graphql" }), "`connection`"),
            (
                json!({ "style": "graphql", "connection": "data.projects" }),
                "`connection`",
            ),
            (
                json!({ "style": "graphql", "connection": "/data/projects", "next": "/x" }),
                "`next`",
            ),
            (
                json!({ "style": "link", "connection": "/data/projects" }),
                "`connection`",
            ),
        ] {
            let problems = problems_of(value.clone());
            assert!(
                problems.iter().any(|p| p.contains(field)),
                "{value}: {problems:?}"
            );
        }
    }

    /// A GraphQL page's next is its connection's `endCursor` while `hasNextPage` says there is one: a cursor for the same
    /// query, not an address.
    #[test]
    fn a_graphql_page_s_next_is_its_cursor_while_there_is_a_next_page() {
        let style = Style::GraphQl {
            connection: "/data/projects".into(),
        };
        let at = "https://gitlab.example/api/graphql";
        let page = |has: Value, end: Value| {
            json!({ "data": { "projects": { "nodes": [], "pageInfo": { "hasNextPage": has, "endCursor": end } } } })
                .to_string()
        };
        assert_eq!(
            following(
                &style,
                at,
                None,
                &[],
                page(json!(true), json!("c1")).as_bytes()
            )
            .unwrap(),
            Some(Next::After("c1".into()))
        );
        assert_eq!(
            following(
                &style,
                at,
                Some("c1"),
                &[],
                page(json!(false), json!("c2")).as_bytes()
            )
            .unwrap(),
            None
        );
        assert_eq!(
            following(
                &style,
                at,
                Some("c1"),
                &[],
                page(json!(false), Value::Null).as_bytes()
            )
            .unwrap(),
            None
        );
        for (bad, why) in [
            (page(json!(true), Value::Null), "endCursor"),
            (page(json!(true), json!("")), "endCursor"),
            (page(json!(true), json!("c1")), "itself"),
            (page(json!("yes"), json!("c2")), "hasNextPage"),
            (json!({ "data": { "other": {} } }).to_string(), "pageInfo"),
        ] {
            let got = following(&style, at, Some("c1"), &[], bad.as_bytes());
            assert!(
                got.as_ref().is_err_and(|e| e.contains(why)),
                "{bad}: {got:?}"
            );
        }
        // The address styles' next is an address, as `next` says.
        let link = vec![format!("<{at}?page=2>; rel=\"next\"")];
        assert_eq!(
            following(&Style::Link, at, None, &link, b"").unwrap(),
            Some(Next::At(format!("{at}?page=2")))
        );
    }

    fn param() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9_]{0,8}"
    }

    proptest! {
        /// An offset is the one before it and the items read since, the address's other parameters as they were.
        #[test]
        fn an_offset_is_the_last_one_and_the_items_read(
            name in param(),
            others in prop::collection::btree_map("[a-z]{1,4}", "[a-z0-9]{0,4}", 0..3),
            start in prop::option::of(0u64..1_000_000),
            count in 0usize..20,
        ) {
            prop_assume!(!others.contains_key(&name));
            let mut url = url::Url::parse("https://h.example/list").unwrap();
            for (k, v) in &others {
                url.query_pairs_mut().append_pair(k, v);
            }
            if let Some(start) = start {
                url.query_pairs_mut().append_pair(&name, &start.to_string());
            }
            let body = serde_json::to_vec(&vec![0; count]).unwrap();
            let style = Style::Offset { param: name.clone(), items: String::new() };
            let got = next(&style, url.as_str(), &[], &body).unwrap();
            if count == 0 {
                prop_assert_eq!(got, None);
            } else {
                let got = url::Url::parse(&got.unwrap()).unwrap();
                let pairs: Vec<(String, String)> = got.query_pairs().into_owned().collect();
                let expected = (start.unwrap_or(0) + count as u64).to_string();
                prop_assert_eq!(pairs.iter().filter(|(k, _)| k == &name).map(|(_, v)| v.clone()).collect::<Vec<_>>(), vec![expected]);
                for (k, v) in &others {
                    prop_assert!(pairs.contains(&(k.clone(), v.clone())));
                }
                prop_assert_eq!(got.host_str(), Some("h.example"));
            }
        }

        /// Whatever a page says, a next page it names is on the source's own scheme, host and port, and is not the page.
        #[test]
        fn a_next_page_is_always_on_the_source_s_host(
            scheme in prop_oneof![Just("https"), Just("http")],
            host in prop_oneof![Just("h.example"), Just("other.example"), Just("h.example.evil")],
            port in prop::option::of(prop_oneof![Just(443u16), Just(8443)]),
            path in "/[a-z]{0,6}(\\?p=[0-9])?",
            by_link in any::<bool>(),
        ) {
            let current = "https://h.example/list";
            let address = match port {
                Some(port) => format!("{scheme}://{host}:{port}{path}"),
                None => format!("{scheme}://{host}{path}"),
            };
            let got = if by_link {
                next(&Style::Link, current, &[format!("<{address}>; rel=\"next\"")], b"")
            } else {
                next(&Style::Cursor { next: "/n".into() }, current, &[], json!({ "n": address }).to_string().as_bytes())
            };
            if let Ok(Some(next)) = got {
                let next = url::Url::parse(&next).unwrap();
                let current = url::Url::parse(current).unwrap();
                prop_assert_eq!(next.origin(), current.origin());
                prop_assert_ne!(next, current);
            }
        }

        /// A cursor is followed only forward: whatever cursor a page names, it is the next page's exactly when the page
        /// says there is one and it is not the cursor the page was asked for.
        #[test]
        fn a_cursor_is_followed_exactly_while_the_page_says_there_is_more(
            has in any::<bool>(),
            end in prop::option::of("[a-z0-9=]{1,8}"),
            asked in prop::option::of("[a-z0-9=]{1,8}"),
        ) {
            let style = Style::GraphQl { connection: "/data/c".into() };
            let page = json!({ "data": { "c": { "pageInfo": { "hasNextPage": has, "endCursor": end } } } }).to_string();
            let got = following(&style, "https://h.example/api/graphql", asked.as_deref(), &[], page.as_bytes());
            match (has, &end) {
                (false, _) => prop_assert_eq!(got, Ok(None)),
                (true, Some(end)) if Some(end) != asked.as_ref() => prop_assert_eq!(got, Ok(Some(Next::After(end.clone())))),
                (true, _) => prop_assert!(got.is_err()),
            }
        }
    }
}
