# 🔱 Shipwreck - A highly configurable docker socket proxy [![Build Status](https://travis-ci.org/Drakulix/shipwreck.svg?branch=master)](https://travis-ci.org/Drakulix/shipwreck)
> When all hope is lost anyway make the best out of a difficult situation

## Motivation

Exposing your docker socket to a container basically gives that container root permissions.
You should **never** do this in a production environment, but for less security-relevant environments
this *may* provide a high degree of comfort. E.g. auto-configuring
[reverse](https://github.com/jwilder/nginx-proxy) [proxies](https://github.com/containous/traefik),
[real-time statistics](https://github.com/netdata/netdata/wiki/monitoring-cgroups) or
[auto](https://github.com/containrrr/watchtower) [updates](https://github.com/pyouroboros/ouroboros).

Most of these use-cases only need to readout your current container status, but do not need to
create new containers. Or you may wish to hide certain containers. For these cases you may use
`shipwreck` to create a filtering proxy for your docker socket.

## Usage

```
🔱 Shipwreck 1.0
Victor Brekenfeld <shipwreck@drakulix.de>
Proxy docker.sock for safe(r) container exposure

USAGE:
    shipwreck [FLAGS] [OPTIONS] --to <URI>

FLAGS:
    -F, --force      Overwrite unix socket file, if it exists and required
    -h, --help       Prints help information
    -q, --quiet      Do not log anything
    -V, --version    Prints version information
    -v               Sets the level of verbosity

OPTIONS:
    -c, --filter_config <FILE>    Sets a custom filter config file (defaults to block all POST requests)
    -f, --from <URI>              Docker Host (defaults to unix:///var/run/docker.sock)
    -m, --mode <MODE>             Mode/Permissions of the created socket, if given a "unix:"/"file:" URI (defaults to 660)
    -t, --to <URI>                Sets the socket to create
```

Accepted URIs are either:

- `tcp://`/`http://`
- `unix://`/`file://`
- (`tls://`/`https://` are not yet supported)

`unix://` or `file://` URIs need a host to parse correctly, although it is irrelevant for a unix-socket (e.g. `unix://localhost/var/run/docker.sock`).

## Filter configuration

Shipwreck can be configured using a combination of glob-patterns and [jmespath](http://jmespath.org/)
to filter the resulting json.

Shipwrecks default config blocks all `POST`-requests.

```toml
[POST]
"*" = "block"
```

All HTTP-Methods are supported, using `*` all Methods can be filtered.
Since rules are applied in order this can be used to filter all but some calls.

For example `netdata` only needs access to the
[`/containers` calls](https://docs.docker.com/engine/api/v1.39/#tag/Container).
Furthermore only `GET`-calls are required. The following config can be used to apply those filters:
```toml
[GET]
"/containers*/json" = "@"
"*" = "block"

[*]
"*" = "block"
```

The identifier `block` has a special meaning to `shipwreck`. If a rule matches `block`, `403 - Forbidden`
is returned by a http call. Otherwise the value is parsed as a [jmespath](http://jmespath.org/).
Using `@` the json input can be passed through (this is standard jmespath syntax).

Much more complex filtering is possible. E.g. you may use ``[?Names != `["/netdata"]`]`` on `/containers/json`
to hide a netdata container from itself (assuming your netdata-container is actually named *netdata*). Instead of returning a `403` you may also craft empty responses
for tools, that no not handle http errors very well.

## Usage with docker

`shipwreck` is hosted on the docker hub as well.

So you can easily deploy it e.g. as part of a `docker-compose.yml`:
```yml
netdata:
  cap_add:
  - SYS_PTRACE
  depends_on:
  - netdata-docker-proxy
  expose:
  - 19999:19999/tcp
  image: titpetric/netdata
  restart: unless-stopped
  volumes:
  - /proc:/host/proc:ro
  - /sys:/host/sys:ro
  - /sockets/netdata:/var/run:ro
  - /config/netdata:/etc/netdata
netdata-docker-proxy:
  image: drakulix/shipwreck
  restart: unless-stopped
  command: --to=file://localhost/target/docker.sock --force
  volumes:
  - /sockets/netdata:/target
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

## FAQ

> But why should I trust shipwreck?

Good question and the answer is, you shouldn't. Here are some steps to ease the process:
1. Read the source: https://github.com/Drakulix/shipwreck
2. Pin your version - when using docker - don't use `latest`. (So the executable running is always matching the source you verified yourself.)
3. Common sense: Rather trust one small program, then trusting a bunch of different applications utilizing your `docker.sock`.

> I mount my socket using `-v /var/run/docker.sock:/var/run/docker.sock`**`:ro`**, doesn't that mean it is read only?

Read-only does not work that way for unix-sockets. You are still allowed to communicate with a socket and therefor write to it
(and the process needs to do that to call docker's api endpoints). POST requests are no exception to this rule.

## Similar projects

The following similar projects were found prior to building `shipwreck` and were providing the necessary motivation.
`shipwreck` tries to work around shortcomings either in configuration options or easy of use. They do provide
valuable alternatives you should definitely look into, if you are considering to use `shipwreck`.

- [`doxy`](https://github.com/qnib/doxy)
- [`docker-socket-proxy`](https://github.com/Tecnativa/docker-socket-proxy)
- [`sockguard`](https://github.com/buildkite/sockguard)
- [`docker-socket-acl`](https://github.com/titpetric/docker-proxy-acl)

## Contributing

`shipwreck` is written in [rust](https://rust-lang.org) and compiled against musl-libc to provide a single statically linked executable.
Contributions are highly welcome, however before you jump into development, please open an issue and start a discussion about any new features.
