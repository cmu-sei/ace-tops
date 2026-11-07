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

//! The client makes what is missing and nothing twice, against a stand-in for GitLab's REST API.

use gitlab_seed::dataset::{Group, Package, Project, User};
use gitlab_seed::gitlab::Gitlab;
use gitlab_seed::oci::image;
use gitlab_seed::registry::Registry;
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "glpat-test";

async fn gitlab(server: &MockServer) -> Gitlab {
    Gitlab::new(server.uri().parse().unwrap(), TOKEN.to_string(), None, None).unwrap()
}

fn user() -> User {
    User {
        username: "seed-user-01".into(),
        name: "Seed User 01".into(),
        email: "seed-user-01@seed.example".into(),
    }
}

#[tokio::test]
async fn a_user_that_is_there_is_not_made_again() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/users"))
        .and(query_param("username", "seed-user-01"))
        .and(header("PRIVATE-TOKEN", TOKEN))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "id": 7, "username": "seed-user-01" }])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/users"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    assert_eq!(gitlab(&server).await.ensure_user(&user()).await.unwrap(), 7);
}

#[tokio::test]
async fn a_user_that_is_not_there_is_made_once_with_no_password_known_to_anyone() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/api/v4/users"))
        .and(body_partial_json(json!({ "username": "seed-user-01", "force_random_password": true, "skip_confirmation": true })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 8 })))
        .expect(1).mount(&server).await;
    assert_eq!(gitlab(&server).await.ensure_user(&user()).await.unwrap(), 8);
}

#[tokio::test]
async fn a_group_is_found_by_its_full_path_and_a_subgroup_made_under_its_parent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/groups/polar-seed%2Fplatform"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/groups"))
        .and(body_partial_json(
            json!({ "path": "platform", "parent_id": 3 }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 4 })))
        .expect(1)
        .mount(&server)
        .await;
    let g = Group {
        path: "platform".into(),
        full_path: "polar-seed/platform".into(),
        parent: Some("polar-seed".into()),
    };
    assert_eq!(
        gitlab(&server)
            .await
            .ensure_group(&g, Some(3))
            .await
            .unwrap(),
        4
    );
}

#[tokio::test]
async fn a_member_that_is_there_is_left_and_one_that_is_not_is_added() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/groups/4/members/7"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 7 })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/groups/4/members/8"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/groups/4/members"))
        .and(body_partial_json(
            json!({ "user_id": 8, "access_level": 30 }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 8 })))
        .expect(1)
        .mount(&server)
        .await;
    let g = gitlab(&server).await;
    g.ensure_member(4, 7, 30).await.unwrap();
    g.ensure_member(4, 8, 30).await.unwrap();
}

#[tokio::test]
async fn a_project_is_made_with_a_main_branch_and_a_ci_file_only_once() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/polar-seed%2Fproject-01"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST")).and(path("/api/v4/projects"))
        .and(body_partial_json(json!({ "path": "project-01", "namespace_id": 3, "initialize_with_readme": true, "default_branch": "main" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 11 })))
        .expect(1).mount(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/11/repository/files/.gitlab-ci.yml"))
        .and(query_param("ref", "main"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "file_path": ".gitlab-ci.yml" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/11/repository/files/.gitlab-ci.yml"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    let g = gitlab(&server).await;
    let p = Project {
        path: "project-01".into(),
        namespace: "polar-seed".into(),
        full_path: "polar-seed/project-01".into(),
        ci: None,
        readme: true,
    };
    assert_eq!(g.ensure_project(&p, 3).await.unwrap(), 11);
    assert!(
        !g.ensure_file(11, ".gitlab-ci.yml", "x", "seed")
            .await
            .unwrap(),
        "there already: not committed again"
    );
}

#[tokio::test]
async fn an_answer_gitlab_refuses_is_an_error_naming_the_call_and_never_the_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/users"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let why = gitlab(&server)
        .await
        .ensure_user(&user())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        why.contains("/api/v4/users") && why.contains("500"),
        "{why}"
    );
    assert!(!why.contains(TOKEN), "{why}");
}

#[tokio::test]
async fn a_failed_pipeline_is_asked_to_run_again() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/11/pipelines/5/retry"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({ "id": 5, "status": "pending" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    gitlab(&server).await.retry_pipeline(11, 5).await.unwrap();
}

#[tokio::test]
async fn a_mirror_is_made_with_no_readme_so_its_history_can_be_pushed_whole() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/polar-seed%2Fpolar"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects"))
        .and(body_partial_json(
            json!({ "path": "polar", "initialize_with_readme": false }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 31 })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/31/repository/branches/main"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let g = gitlab(&server).await;
    let p = Project {
        path: "polar".into(),
        namespace: "polar-seed".into(),
        full_path: "polar-seed/polar".into(),
        ci: None,
        readme: false,
    };
    assert_eq!(g.ensure_project(&p, 3).await.unwrap(), 31);
    assert!(!g.has_branch(31, "main").await.unwrap());
}

#[tokio::test]
async fn a_package_that_is_there_is_left_and_one_that_is_not_is_put_file_by_file() {
    let server = MockServer::start().await;
    let package = Package {
        project: "polar-seed/project-03".into(),
        name: "seed-tools".into(),
        version: "1.0.0".into(),
        files: vec![
            ("README.txt".into(), "a".into()),
            ("tools.txt".into(), "b".into()),
        ],
    };
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/13/packages"))
        .and(query_param("package_name", "seed-tools"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    for file in ["README.txt", "tools.txt"] {
        Mock::given(method("PUT"))
            .and(path(format!(
                "/api/v4/projects/13/packages/generic/seed-tools/1.0.0/{file}"
            )))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(json!({ "message": "201 Created" })),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    assert!(
        gitlab(&server)
            .await
            .ensure_package(13, &package)
            .await
            .unwrap()
    );
    let there = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/13/packages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "id": 1, "name": "seed-tools", "version": "1.0.0" }])),
        )
        .mount(&there)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&there)
        .await;
    assert!(
        !gitlab(&there)
            .await
            .ensure_package(13, &package)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_image_is_pushed_with_a_token_from_gitlab_its_blobs_once_and_each_tag() {
    let gitlab_server = MockServer::start().await;
    let registry = MockServer::start().await;
    let img = image(&[("seed.txt", b"seed")]);
    Mock::given(method("GET"))
        .and(path("/jwt/auth"))
        .and(query_param("service", "container_registry"))
        .and(query_param(
            "scope",
            "repository:polar-seed/project-02:push,pull",
        ))
        .and(header("authorization", "Basic cm9vdDpnbHBhdC10ZXN0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": "registry-jwt" })))
        .expect(1)
        .mount(&gitlab_server)
        .await;
    // The config is there already; the layer is not.
    Mock::given(method("HEAD"))
        .and(path(format!(
            "/v2/polar-seed/project-02/blobs/{}",
            img.config_digest
        )))
        .respond_with(ResponseTemplate::new(200))
        .mount(&registry)
        .await;
    Mock::given(method("HEAD"))
        .and(path(format!(
            "/v2/polar-seed/project-02/blobs/{}",
            img.layer_digest
        )))
        .respond_with(ResponseTemplate::new(404))
        .mount(&registry)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/polar-seed/project-02/blobs/uploads/"))
        .and(header("authorization", "Bearer registry-jwt"))
        .respond_with(ResponseTemplate::new(202).insert_header(
            "Location",
            "/v2/polar-seed/project-02/blobs/uploads/u1?_state=s",
        ))
        .expect(1)
        .mount(&registry)
        .await;
    Mock::given(method("PUT"))
        .and(path("/v2/polar-seed/project-02/blobs/uploads/u1"))
        .and(query_param("digest", img.layer_digest.as_str()))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&registry)
        .await;
    for tag in ["1.0", "latest"] {
        Mock::given(method("PUT"))
            .and(path(format!("/v2/polar-seed/project-02/manifests/{tag}")))
            .and(header(
                "content-type",
                "application/vnd.oci.image.manifest.v1+json",
            ))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&registry)
            .await;
    }
    let r = Registry::new(
        registry.uri().parse().unwrap(),
        gitlab_server.uri().parse().unwrap(),
        TOKEN.to_string(),
        None,
        None,
        None,
    )
    .unwrap();
    r.push(
        "polar-seed/project-02",
        &img,
        &["1.0".to_string(), "latest".to_string()],
    )
    .await
    .unwrap();
}
