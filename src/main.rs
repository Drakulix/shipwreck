use std::{
    collections::{BTreeMap, HashMap},
    convert::{TryFrom, TryInto},
    io::{self, Read},
    fs::{self, File},
    fmt, error,
    str::FromStr,
    path::PathBuf,
    net::SocketAddr,
};
use clap::{App, Arg};
use uri::Uri;
use glob::Pattern;
use jmespath::Expression;
use futures::{Future, Stream};
use failure::{Fail, Error};
use hyper::{
    client::{
        connect::{Connect, Connected},
        HttpConnector,
    },
    Client, Body, Request, Response, Method, StatusCode,
    service::{Service, NewService},
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

#[derive(Debug)]
enum ServiceError {
    MethodConversionError(MethodConversionError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unable to convert method type.\nCause: {}", match self {
            ServiceError::MethodConversionError(x) => x,
        })
    }
}

impl error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            &ServiceError::MethodConversionError(ref x) => &x,
        })
    }
}

impl NewService for ProxyService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = ServiceError;
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

type Return = Box<Future<Item = Response<Body>, Error = ServiceError> + Send>;

impl Service for ProxyService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = ServiceError;
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
                                        futures::future::ok::<_, ServiceError>(bytes)
                                    }).map(move |json| {
                                        let data: jmespath::Variable = serde_json::from_slice(&json).unwrap();
                                        let result = path.search(data)
                                            .map_err(|err| log::error!("Execution Error: {}", err))
                                            .expect("Could not run jmespath");
                                        let body = Body::from(serde_json::to_vec(&*result).unwrap());
                                        Response::from_parts(parts, body)
                                    })) as Box<Future<Item = Response<Body>, Error = ServiceError> + Send>
                                }
                            };
                            Box::new(futures::future::ok(resp)) as Box<Future<Item = Response<Body>, Error = ServiceError> + Send>
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
            if let Some(filters) = config.get(&req.method().try_into()?) {
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
                    .keep_alive(false)
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

#[derive(Debug, Fail)]
enum SocketConversionError {
    #[fail(display = "unix:/file: uri has no path")]
    UriHasNoPath,

    #[fail(display = "Unknown uri type ({}), use one of 'unix', 'file', 'tcp', 'http', 'tls', 'https'", uriType)]
    UnknownUriType {
        uriType: String,
    }
}

impl TryFrom<uri::Uri> for Socket {
    type Error = SocketConversionError;

    fn try_from(uri: uri::Uri) -> Result<Socket, SocketConversionError> {
        match &*uri.scheme {
            "unix" | "file" => Ok(Socket::Unix(PathBuf::from(uri.path.ok_or(SocketConversionError::UriHasNoPath)?))),
            "tcp" | "http" => Ok(Socket::Network(
                format!("{}{}",
                    uri.host.unwrap(),
                    uri.port
                        .map(|port| if port == 80 { String::new() } else { format!(":{}", port) })
                        .unwrap_or_default()
                )
            )),
            "tls" | "https" => Ok(Socket::EncryptedNetwork(
                format!("{}{}",
                    uri.host.unwrap(),
                    uri.port
                        .map(|port| if port == 443 { String::new() } else { format!(":{}", port) })
                        .unwrap_or_default()
                )
            )),
            x => Err(SocketConversionError::UnknownUriType { uriType: x }),
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

#[derive(Debug, Fail)]
enum MethodConversionError {
    #[fail(display = "Unknown Method: {}", method)]
    UnknownMethod {
        method: String,
    }
}

impl TryFrom<&Method> for MethodType {
    type Error = MethodConversionError;
    fn try_from(method: &Method) -> Result<Self, Self::Error> {
        match method.as_str() {
            "GET" => Ok(MethodType::GET),
            "POST" => Ok(MethodType::POST),
            "PUT" => Ok(MethodType::PUT),
            "DELETE" => Ok(MethodType::DELETE),
            "HEAD" => Ok(MethodType::HEAD),
            "OPTIONS" => Ok(MethodType::OPTIONS),
            "CONNECT" => Ok(MethodType::CONNECT),
            "PATCH" => Ok(MethodType::PATCH),
            "TRACE" => Ok(MethodType::TRACE),
            _ => Err(MethodConversionError::UnknownMethod { method: method.as_str() }),
        }
    }
}

#[derive(Debug, Fail)]
enum MainError {
    #[fail(display = "Error initializing logging system")]
    LogSystem(#[fail(cause)] log::SetLoggerError),

    #[fail(display = "Error opening filter config file")]
    OpenConfigError(#[fail(cause)] io::Error),

    #[fail(display = "Error reading filter config file")]
    ReadConfigError(#[fail(cause)] io::Error),

    #[fail(display = "Error parsing filter config file")]
    ParseConfigError(#[fail(cause)] toml::de::Error),

    #[fail(display = "Error parsing glob pattern: '{:?} = {:?}'", pattern, expr)]
    GlobParseError {
        pattern: String,
        expr: String,
        #[fail(cause)] cause: glob::PatternError
    },

    #[fail(display = "Error parsing jmespath: '{:?} = {:?}'", pattern, expr)]
    JmespathParseError {
        pattern: String,
        expr: String,
        #[fail(cause)] cause: jmespath::JmespathError
    },
}

fn main() -> Result<(), Box<std::error::Error>> {
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
    let from = Uri::new(matches.value_of("from").unwrap_or("unix:///var/run/docker.sock")).try_into()?;
    let to = Uri::new(matches.value_of("to").unwrap()).try_into()?;
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
    if let Err(err) = simplelog::TermLogger::init(verbosity, Default::default()) {
        simplelog::SimpleLogger::init(verbosity, Default::default()).map_err(|err| MainError::LogSystem(err))?;
        log::debug!("Not running on a tty: {:?}", err);
    }

    // config
    let mut config_bytes = Vec::new();
    File::open(config_path)
        .map_err(|err| MainError::OpenConfigError(err))?
        .read_to_end(&mut config_bytes)
        .map_err(|err| MainError::ReadConfigError(err))?;
    let config: Config = {
        let raw_conf: HashMap<MethodType, BTreeMap<String, String>> =
            toml::from_slice(&config_bytes).map_err(|err| MainError::ParseConfigError(err));
        raw_conf.into_iter()
        .map(|(key, value)| {
            (key, value.into_iter().map(|(pattern, expr)| {
                (
                    Pattern::new(&pattern).map_err(|cause| MainError::GlobParseError { pattern, expr, cause })?,
                    if expr.to_lowercase() == "block" {
                        None
                    } else {
                        Some(jmespath::compile(&expr).map_err(|cause| MainError::JmespathParseError { pattern, expr, cause })?)
                    }
                )
            }).collect())
        }).collect()
    };

    log::info!("😱 Shipwreck initializing! The crew is drowning");
    run(from, to, config, overwrite)?;
    Ok(())
}
