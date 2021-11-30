use http::Request;
use tower_http::request_id::RequestId;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct MakeRequestUuid;

impl tower_http::request_id::MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _: &Request<B>) -> Option<RequestId> {
        let request_id = Uuid::new_v4().to_string().parse().ok()?;
        Some(RequestId::new(request_id))
    }
}
