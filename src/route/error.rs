use rocket::Request;
use rocket::http::Status;

use response::Response;

#[catch(404)]
pub fn not_found(req: &Request) -> Response {
    Response {
        status: Status::NotFound,
        data: json!({
            "data": {
                "message": format!("'{path}' is not found", path=req.uri().path()),
            }
        }),
    }
}

#[catch(422)]
pub fn unprocessable_entity(_req: &Request) -> Response {
    Response {
        status: Status::UnprocessableEntity,
        data: json!({
            "data": {
                "message": "The input is invalid".to_string(),
            }
        }),
    }
}
