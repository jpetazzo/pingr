# pingr

On request, this http server will get a list of assets from
[collins](tumblr.github.io/collins/), send http requests configured by
the `-t` flag and return HTTP 500 with a plain text error message in
case any request failed.

It takes the path as collins attribute filter. A request to
`/secondary_role;foobar` will send requests to all assets with the
role `foobar`.

By setting the `-auth.pass` flag, it will require HTTP basic auth.

# Usage

    Usage of ./pingr:
      -=5s: connect timeout for tests
      -auth.pass="": password for basic auth
      -auth.user="ping": user for basic auth
      -listen="0.0.0.0:8000": adress to listen on
      -pass="admin:first": collins password
      -status="Allocated": only assets with this status
      -timeout=5s: rw timeout for tests
      -url="http://localhost:9000/api": collins api url
      -user="blake": collins username

After starting `pingr`, you can check collins assets based on this path schema:

    /pool/test/port/asset type[/optional/path/to/use/for/http/test][?attributeA=valueA&attributeB=valueB...]

This will find all assets for given `asset type` and optional `attribute`s, get
their address(es) from `pool` and use `test` on `port` with optional `path`.

# Tests
Currently there are two tests implemented:

- http: Sends an http request, status code < 200 or > 400 are considered errors
- tcp: Connects to port, connection failures are considered errors. Path is
  ignored.

# Example
This request will check if ssh is reachable on `int` addresses of all
`server_node` assets with primary role `web` and secondary role `default`:

    /int/tcp/22/server_node?primary_role=web&secondary_role=default

This would check the assets 'dmz' adresses via http on port `80` with path
`foo/bar` instead:

    /dmz/tcp/80/server_node/foo/bar?primary_role=web&secondary_role=default

