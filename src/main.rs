use std::{
    collections::{BTreeMap, HashMap},
    io::{self, Read},
    fs::{self, File},
    str::FromStr,
    path::PathBuf,
    net::SocketAddr,
};
use clap::{App, Arg};
use uri::Uri;
use glob::Pattern;
use jmespath::Expression;
use futures::{Future, Stream};
use hyper::{
    client::{
        connect::{Connect, Connected},
        HttpConnector,
    },
    Client, Body, Request, Response, Method, StatusCode,
    service::{Service, NewService}, error::Error,
};
use hyperlocal::{UnixConnector};
use tokio_io::{AsyncRead, AsyncWrite};
use serde::Deserialize;

type Filters = BTreeMap<Pattern, Option<Expression<'static>>>;
type Config = HashMap<MethodType, Filters>;

fn clone_expr(expr: &Expression) -> Expression<'static> {
    jmespath::compile(expr.as_str()).unwrap()
}

struct ProxyService {
    from: Socket,
    config: Config,
}

impl NewService for ProxyService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Service = ProxyService;
    type Future = Box<Future<Item = ProxyService, Error = Error> + Send>;
    type InitError = Error;
    fn new_service(&self) -> Self::Future {
        Box::new(futures::future::ok(self.clone()))
    }
}

impl Clone for ProxyService {
    fn clone(&self) -> Self {
        ProxyService {
            from: self.from.clone(),
            config: self.config.iter().map(|(key, value)| {
                (key.clone(), value.iter().map(|(key, value)| {
                    (key.clone(), value.as_ref().map(|value| clone_expr(value))) // this is stupid
                }).collect())
            }).collect(),
        }
    }
}

type Return = Box<Future<Item = Response<Body>, Error = hyper::error::Error> + Send>;

impl Service for ProxyService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Error;
    type Future = Return;
    fn call(&mut self, mut req: Request<Self::ReqBody>) -> Self::Future {
        fn proxy<
            T: AsyncRead + AsyncWrite + Send + 'static,
            F: Future<Item = (T, Connected), Error = std::io::Error> + Send + 'static,
            C: Connect<Transport=T, Error=std::io::Error, Future=F> + 'static,
        >(client: Client<C, Body>, config: &Config, mut req: Request<Body>) -> Return {

            fn filter<
                T: AsyncRead + AsyncWrite + Send + 'static,
                F: Future<Item = (T, Connected), Error = std::io::Error> + Send + 'static,
                C: Connect<Transport=T, Error=std::io::Error, Future=F> + 'static,
            >(client: &Client<C, Body>, req: Request<Body>, filters: &Filters) -> Result<Return, Request<Body>> {
                match filters.iter().find(|(pattern, _)| pattern.matches(req.uri().path())) {
                    Some((_, None)) => return Ok(Box::new(futures::future::ok(Response::builder().status(StatusCode::FORBIDDEN).body(Body::empty()).unwrap()))),
                    Some((_, Some(path))) => {
                        let path = clone_expr(path);
                        return Ok(Box::new(client.request(req).and_then(move |resp| {
                            if resp.status().is_success() {
                                if resp.headers().get("Content-Type").map(|val| val == "application/json").unwrap_or(false) {
                                    let (parts, body) = resp.into_parts();
                                    return Box::new(body.fold(Vec::new(), |mut bytes, chunk| {
                                        bytes.extend_from_slice(&chunk);
                                        futures::future::ok::<_, hyper::Error>(bytes)
                                    }).map(move |json| {
                                        let data: jmespath::Variable = serde_json::from_slice(&json).unwrap();
                                        let result = path.search(data).expect("Could not run jmespath");
                                        let body = Body::from(serde_json::to_vec(&*result).unwrap());
                                        Response::from_parts(parts, body)
                                    })) as Box<Future<Item = Response<Body>, Error = hyper::error::Error> + Send>
                                }
                            };
                            Box::new(futures::future::ok(resp)) as Box<Future<Item = Response<Body>, Error = hyper::error::Error> + Send>
                        })))
                    },
                    _ => Err(req),
                }
            }

            if let Some(filters) = config.get(&MethodType::ANY) {
                match filter(&client, req, filters) {
                    Ok(result) => return result,
                    Err(old_req) => { req = old_req; },
                }
            }
            if let Some(filters) = config.get(&req.method().into()) {
                match filter(&client, req, filters) {
                    Ok(result) => return result,
                    Err(old_req) => { req = old_req; },
                }
            }
            Box::new(client.request(req))
        }

        match &self.from {
            &Socket::Unix(ref path) => {
                let client = Client::builder()
                    .keep_alive(false) // without this the connection will remain open
                    .build::<_, Body>(UnixConnector::new());
                *req.uri_mut() = hyperlocal::Uri::new(path,
                    req.uri()
                    .path_and_query()
                    .expect("Request has no path. (This should never happen)")
                    .as_str()
                ).into();
                proxy(client, &self.config, req)
            },
            &Socket::Network(ref addr) => {
                let client = Client::builder()
                    .keep_alive(false)
                    .build::<_, Body>(HttpConnector::new(1));
                *req.uri_mut() = hyper::Uri::builder()
                    .scheme("http")
                    .authority(&**addr)
                    .path_and_query(
                        req.uri()
                        .path_and_query()
                        .expect("Request has no path. (This should never happen)")
                        .clone()
                    )
                    .build().unwrap();
                proxy(client, &self.config, req)
            },
            &Socket::EncryptedNetwork(_) => unimplemented!(),
        }
    }
}

fn run(from: Socket, to: Socket, config: Config, force: bool) -> io::Result<()> {
    match to {
        Socket::Unix(path) => {
            if path.exists() {
                if force {
                    fs::remove_file(&path)?;
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("A file at {:?} already exists, use --force to overwrite.", path)
                    ));
                }
            }

            let svr = hyperlocal::server::Server::bind(&path, ProxyService { from, config })?;
            log::info!("🐙 Successfully sunken. Serving Cthulhu on unix://{:?}", path);
            svr.run()?;

            if let Err(err) = fs::remove_file(path) {
                if err.kind() != io::ErrorKind::NotFound {
                    return Err(err);
                }
            }
        },
        Socket::Network(addr) => {
            let svr = hyper::server::Server::bind(&SocketAddr::from_str(&addr).expect("Cannot parse listen uri as SocketAddress"))
                    .http1_only(true)
                    .serve(ProxyService { from, config });
            log::info!("🐙 Successfully sunken. Serving Cthulhu on tcp://{}", addr);
            hyper::rt::run(svr.map_err(|e| {
               log::error!("Server error: {}", e);
            }));
        },
        Socket::EncryptedNetwork(_) => unimplemented!(),
    }

    Ok(())
}

#[derive(Clone)]
enum Socket {
    Unix(PathBuf),
    Network(String),
    EncryptedNetwork(String),
}

impl From<uri::Uri> for Socket {
    fn from(uri: uri::Uri) -> Socket {
        match &*uri.scheme {
            // TODO better errors, when TryFrom is stable
            "unix" | "file" => Socket::Unix(PathBuf::from(uri.path.expect("unix:/file: uri has no path"))),
            "tcp" | "http" => Socket::Network(
                format!("{}{}",
                    uri.host.unwrap(),
                    uri.port
                        .map(|port| if port == 80 { String::new() } else { format!(":{}", port) })
                        .unwrap_or_default()
                )
            ),
            "tls" | "https" => Socket::EncryptedNetwork(
                format!("{}{}",
                    uri.host.unwrap(),
                    uri.port
                        .map(|port| if port == 443 { String::new() } else { format!(":{}", port) })
                        .unwrap_or_default()
                )
            ),
            _ => panic!("Unknown uri type, use one of 'unix', 'file', 'tcp', 'http', 'tls', 'https'"),
        }
    }
}

#[derive(Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
pub enum MethodType {
    #[serde(rename = "*")]
    ANY,
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    PATCH,
    TRACE,
}

impl From<&Method> for MethodType {
    fn from(method: &Method) -> Self {
        match method.as_str() {
            "GET" => MethodType::GET,
            "POST" => MethodType::POST,
            "PUT" => MethodType::PUT,
            "DELETE" => MethodType::DELETE,
            "HEAD" => MethodType::HEAD,
            "OPTIONS" => MethodType::OPTIONS,
            "CONNECT" => MethodType::CONNECT,
            "PATCH" => MethodType::PATCH,
            "TRACE" => MethodType::TRACE,
            _ => panic!("Unknown Method"),
        }
    }
}

fn main() {
    let matches = App::new("🔱 Shipwreck")
        .version("1.0")
        .author("Victor Brekenfeld <shipwreck@drakulix.de>")
        .about("Proxy docker.sock for safe(r) container exposure")
        .arg(Arg::with_name("filter")
            .short("c")
            .long("filter_config")
            .value_name("FILE")
            .help("Sets a custom filter config file (defaults to block all POST requests)")
            .takes_value(true))
        .arg(Arg::with_name("force")
            .short("F")
            .long("force")
            .help("Overwrite unix socket file, if it exists and required"))
        .arg(Arg::with_name("quiet")
            .short("q")
            .long("quiet")
            .conflicts_with("verbose")
            .help("Do not log anything"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .arg(Arg::with_name("from")
            .short("f")
            .long("from")
            .value_name("URI")
            .takes_value(true)
            .help("Docker Host (defaults to unix:///var/run/docker.sock)"))
        .arg(Arg::with_name("to")
            .short("t")
            .long("to")
            .value_name("URI")
            .takes_value(true)
            .required(true)
            .help("Sets the socket to create"))
        .get_matches();

    // read parameters
    let config_path = matches.value_of("filter").unwrap_or("filter.toml");
    let from = Uri::new(matches.value_of("from").unwrap_or("unix:///var/run/docker.sock")).unwrap().into();
    let to = Uri::new(matches.value_of("to").unwrap()).unwrap().into();
    let overwrite = matches.is_present("force");
    let verbosity = match (matches.is_present("quiet"), matches.occurrences_of("verbose")) {
        (true, _) => simplelog::LevelFilter::Off,
        (_, 0)=> simplelog::LevelFilter::Error,
        (_, 1)=> simplelog::LevelFilter::Warn,
        (_, 2)=> simplelog::LevelFilter::Info,
        (_, 3)=> simplelog::LevelFilter::Debug,
        (_, _) => simplelog::LevelFilter::Trace,
    };

    // initialize logging
    if simplelog::TermLogger::init(verbosity, Default::default()).is_err() {
        simplelog::SimpleLogger::init(verbosity, Default::default()).expect("Error initializing logging system");
    }

    // config
    let mut config_bytes = Vec::new();
    File::open(config_path)
        .expect("Unable to open filter configuration file")
        .read_to_end(&mut config_bytes)
        .expect("Unable to read filter configuration file");
    let config: Config = {
        let raw_conf: HashMap<MethodType, BTreeMap<String, String>> =
            toml::from_slice(&config_bytes).expect("Could not parse filter configuration file");
        raw_conf.into_iter()
        .map(|(key, value)| {
            (key, value.into_iter().map(|(pattern, expr)| {
                (
                    Pattern::new(&pattern).expect("Unable to parse glob pattern"),
                    if expr.to_lowercase() == "block" {
                        None
                    } else {
                        Some(jmespath::compile(&expr).expect("Unable to parse jmespath"))
                    }
                )
            }).collect())
        }).collect()
    };

    log::info!("😱 Leave now! The crew is drowning");
    if let Err(err) = run(from, to, config, overwrite) {
        log::error!("🛳️ Error sinking server: {}", err)
    }
}
