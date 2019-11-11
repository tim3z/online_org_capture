#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use rocket::{
    request::{State, Form, FromRequest, Request, Outcome},
    response::{NamedFile, Redirect, Response, Responder},
    http::Status,
};
use basic_auth_raw::BasicAuthRaw;
use std::{
    path::Path,
    sync::{Mutex, mpsc::{Sender, channel}},
    thread,
    fs::OpenOptions,
    io::Write,
    process::Command,
    env,
};

struct Auth();

impl<'a, 'r> FromRequest<'a, 'r> for Auth {
    type Error = ();

    fn from_request(request: &Request) -> Outcome<Self, Self::Error> {
        let basic = BasicAuthRaw::from_request(request)?;
        if basic.username == env::var("CAPTURE_USER").unwrap() && basic.password == env::var("CAPTURE_PASSWORD").unwrap() {
            Outcome::Success(Auth())
        } else {
            Outcome::Failure((Status::Unauthorized, ()))
        }
    }
}

#[catch(401)]
fn challenge_auth() -> impl Responder<'static> {
    let mut response = Response::new();
    response.set_status(Status::Unauthorized);
    response.set_raw_header("WWW-Authenticate", "Basic");
    response
}

#[derive(FromForm)]
struct Task {
    text: String,
}

#[get("/")]
fn index(_auth: Auth) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/index.html")).ok()
}

#[post("/", data = "<task>")]
fn create(task: Form<Task>, state: State<Mutex<Sender<Task>>>, _auth: Auth) -> Redirect {
    let tx = state.lock().unwrap();
    tx.send(task.into_inner()).unwrap();
    Redirect::to("/")
}

fn main() {
    let (tx, rx) = channel::<Task>();

    thread::spawn(move || {
        for task in rx {
            let mut file = OpenOptions::new().append(true).open(env::var("CAPTURE_TARGET_FILE").unwrap()).expect("Could not open capture file");
            writeln!(file, "** TODO {}", task.text).expect("Could not write to file");
            Command::new(env::var("CAPTURE_OCC_COMMAND").unwrap())
                .arg("files:scan")
                .arg(format!("--path={}", env::var("CAPTURE_NEXTCLOUD_RESCAN_PATH").unwrap()))
                .spawn()
                .expect("Could not trigger rescan");
        }
    });

    rocket::ignite()
        .mount("/", routes![index, create])
        .register(catchers![challenge_auth])
        .manage(Mutex::new(tx))
        .launch();
}
