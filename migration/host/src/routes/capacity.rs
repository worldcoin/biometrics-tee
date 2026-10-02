use axum::{Json, extract::State};
use di_migration_primitives::host_api::Capacity;

use crate::AppState;

/// Waiting plus running jobs and the cap, which the API's admission poll sums across hosts.
pub async fn handler(State(state): State<AppState>) -> Json<Capacity> {
    let queue = state.queue();
    Json(Capacity {
        queued: queue.queued(),
        capacity: queue.capacity().get(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{
        routes,
        test_support::{StubEnclave, job, state_with_capacity},
    };

    #[tokio::test]
    async fn capacity_reports_held_jobs_and_the_cap() {
        let state = state_with_capacity(Arc::new(StubEnclave::default()), 4);
        state.queue().push(job(1)).expect("room");

        let response = routes::handler()
            .with_state(state)
            .oneshot(
                Request::get("/capacity")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should answer");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body should read")
            .to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");

        assert_eq!(body["queued"], 1);
        assert_eq!(body["capacity"], 4);
    }
}
