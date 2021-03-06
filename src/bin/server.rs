use std::env;

use dotenv::dotenv;
use proctitle::set_title;
use rocket_slog::SlogFairing;

use eloquentlog_console_api::logger;
use eloquentlog_console_api::server;
use eloquentlog_console_api::db::init_pool_holder as init_db_pool_holder;
use eloquentlog_console_api::mq::init_pool_holder as init_mq_pool_holder;
use eloquentlog_console_api::ss::init_pool_holder as init_ss_pool_holder;
use eloquentlog_console_api::config::Config;

fn get_env() -> String {
    match env::var("ENV") {
        Ok(ref v) if v == &"test".to_string() => String::from("testing"),
        Ok(v) => v.to_lowercase(),
        Err(_) => String::from("development"),
    }
}

fn main() {
    set_title("eloquentlog: server");
    let name = get_env();

    dotenv().ok();
    let config = Config::from(name.as_str()).expect("failed to get config");
    let logger = logger::get_logger(&config);

    // connection pool holders
    let db_pool_holder = init_db_pool_holder(
        &config.database_url,
        config.database_max_pool_size,
    );
    let mq_pool_holder = init_mq_pool_holder(
        &config.message_queue_url,
        config.message_queue_max_pool_size,
    );
    let ss_pool_holder = init_ss_pool_holder(
        &config.session_store_url,
        config.session_store_max_pool_size,
    );

    server()
        .attach(SlogFairing::new(logger))
        .manage(db_pool_holder)
        .manage(mq_pool_holder)
        .manage(ss_pool_holder)
        .manage(config)
        .launch();
}
