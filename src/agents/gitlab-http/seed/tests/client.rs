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

use gitlab_seed::dataset::{Group, Project, User};
use gitlab_seed::gitlab::Gitlab;
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
