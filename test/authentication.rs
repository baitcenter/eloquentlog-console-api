use rocket::http::{ContentType, Status};

use eloquentlog_backend_api::model::user;

use run_test;

#[test]
fn test_login() {
    run_test(|client, db_conn, _, _, logger| {
        let password = "pa$$w0rD";
        let mut u = user::NewUser {
            name: None,
            username: None,
            email: "foo@example.org".to_string(),

            ..Default::default()
        };
        u.set_password(&password);

        user::User::insert(&u, &db_conn, &logger)
            .unwrap_or_else(|| panic!("Error inserting: {}", u));

        let req =
            client
                .post("/_api/login")
                .header(ContentType::JSON)
                .body(format!(
                    "{{\"username\": \"{}\", \"password\": \"{}\"}}",
                    u.email, password
                ));
        let res = req.dispatch();

        assert_eq!(res.status(), Status::Ok);
    });
}
