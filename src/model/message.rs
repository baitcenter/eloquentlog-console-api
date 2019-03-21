//! # Message model for logging
//!
//! See diesel_tests' custom_types.rs
use std::fmt;

use chrono::{NaiveDateTime, Utc};
use diesel::{self, Insertable, prelude::*};
use diesel::pg::PgConnection;

// use diesel::pg::Pg;
// use diesel::debug_query;

use model::level::LogLevel;
use model::format::LogFormat;
pub use model::level::Level;
pub use model::format::Format;

use request::Message as RequestData;

mod schema {
    table! {
        use diesel::sql_types::*;
        use model::message::LogFormat;
        use model::message::LogLevel;

        messages (id) {
            id -> BigInt,
            code -> Nullable<Varchar>,
            lang -> Varchar,
            level -> LogLevel,
            format -> LogFormat,
            title -> Text,
            content -> Nullable<Text>,
            created_at -> Timestamp,
            updated_at -> Timestamp,
        }
    }

    allow_tables_to_appear_in_same_query!(messages,);
}

pub use self::schema::messages;

/// NewMessage
#[derive(Debug, Insertable)]
#[table_name = "messages"]
pub struct NewMessage {
    pub code: Option<String>,
    pub lang: String,
    pub level: Level,
    pub format: Format,
    pub title: Option<String>,
    pub content: Option<String>,
}

impl fmt::Display for NewMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.title {
            Some(title) => write!(f, "<NewMessage {title}>", title = title),
            None => write!(f, "<NewMessage>"),
        }
    }
}

impl Default for NewMessage {
    fn default() -> Self {
        Self {
            code: None,
            lang: "en".to_string(),
            level: Level::Information,
            format: Format::TOML,
            title: None, // validation error
            content: None,
        }
    }
}

impl From<RequestData> for NewMessage {
    fn from(data: RequestData) -> Self {
        Self {
            code: data.code,
            lang: data.lang.unwrap_or_else(|| "en".to_string()),
            level: Level::from(
                data.level.unwrap_or_else(|| "information".to_string()),
            ),
            format: Format::from(
                data.format.unwrap_or_else(|| "toml".to_string()),
            ),
            title: data.title,
            content: data.content,
        }
    }
}

/// Message
#[derive(AsChangeset, AsExpression, Debug, Identifiable, Queryable)]
#[table_name = "messages"]
pub struct Message {
    pub id: i64,
    pub code: Option<String>,
    pub lang: String,
    pub level: Level,
    pub format: Format,
    pub title: String,
    pub content: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Message {title}>", title = self.title)
    }
}

impl Message {
    pub fn first(id: i64, conn: &PgConnection) -> Option<Self> {
        let q = messages::table.find(id);

        // TODO
        // let sql = debug_query::<Pg, _>(&q).to_string();
        // println!("sql: {}", sql);

        match q.first::<Message>(conn) {
            Err(e) => {
                println!("err: {}", e);
                None
            },
            Ok(m) => Some(m),
        }
    }

    /// Save new message.
    ///
    /// `created_at` and `updated_at` will be filled on PostgreSQL side
    /// using timezone('utc'::text, now()).
    pub fn insert(message: &NewMessage, conn: &PgConnection) -> Option<i64> {
        let q = diesel::insert_into(messages::table)
            .values(message)
            .returning(messages::id);

        // TODO
        // let sql = debug_query::<Pg, _>(&q).to_string();
        // println!("sql: {}", sql);

        match q.get_result::<i64>(conn) {
            Err(e) => {
                println!("err: {}", e);
                None
            },
            Ok(id) => Some(id),
        }
    }

    /// Update a message.
    pub fn update(message: &mut Message, conn: &PgConnection) -> Option<i64> {
        message.updated_at = Utc::now().naive_utc();
        let q = diesel::update(messages::table)
            .set(&*message)
            .filter(messages::id.eq(message.id))
            .returning(messages::id);

        // TODO
        // let sql = debug_query::<Pg, _>(&q).to_string();
        // println!("sql: {}", sql);

        match q.get_result::<i64>(conn) {
            Err(e) => {
                println!("err: {}", e);
                None
            },
            Ok(id) => Some(id),
        }
    }
}

#[cfg(test)]
mod message_test {
    use model::test::run;
    use super::*;

    #[test]
    fn test_insert() {
        run(|conn| {
            let m = NewMessage {
                code: None,
                lang: "en".to_string(),
                level: Level::Information,
                format: Format::TOML,
                title: Some("title".to_string()),
                content: None,
            };
            let result = Message::insert(&m, conn);
            assert!(result.is_some());

            let rows_count: i64 = messages::table
                .count()
                .first(conn)
                .expect("Failed to count rows");
            assert_eq!(1, rows_count);
        })
    }

    #[test]
    fn test_update() {
        run(|conn| {
            let m = NewMessage {
                code: Some("200".to_string()),
                lang: "en".to_string(),
                level: Level::Information,
                format: Format::TOML,
                title: Some("title".to_string()),
                content: None,
            };

            let inserted_id = diesel::insert_into(messages::table)
                .values(&m)
                .returning(messages::id)
                .get_result::<i64>(conn)
                .unwrap_or_else(|_| panic!("Error inserting: {}", m));
            assert_eq!(1, inserted_id);

            let current_title = messages::table
                .filter(messages::id.eq(inserted_id))
                .select(messages::title)
                .first::<String>(conn)
                .expect("Failed to select a row");
            assert_eq!("title", current_title);

            let mut m = Message {
                id: inserted_id,
                code: Some("200".to_string()),
                lang: "en".to_string(),
                level: Level::Information,
                format: Format::TOML,
                title: "updated".to_string(),
                content: Some("content".to_string()),
                created_at: Utc::now().naive_utc(),
                updated_at: Utc::now().naive_utc(),
            };
            let result = Message::update(&mut m, conn);
            assert!(result.is_some());

            let value = messages::table
                .select(messages::title)
                .filter(messages::id.eq(m.id))
                .get_result::<String>(conn)
                .expect("Failed to load");
            assert_eq!("updated", &value);
        })
    }
}
