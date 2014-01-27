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

    Usage of pingr:
      -=5s: connect timeout for tests
      -auth.pass="": password for basic auth
      -auth.user="ping": user for basic auth
      -listen="0.0.0.0:8000": adress to listen on
      -pass="admin:first": collins password
      -status="Allocated": only assets with this status
      -t=: specify urls to test per pool in format pool:url
      -timeout=5s: rw timeout for tests
      -type="SERVER_NODE": only assets with this type
      -url="http://localhost:9000/api": collins api url
      -user="blake": collins username

# Example

    pingr -t int:http://%s:8080/ -t dmz:http://%s:443/ --auth.pass=foobar23

Requests to / using the password 'foobar23' will cause pingr to send
an http request to port 8080 for each address from pool 'int' and
port 443 for each from pool 'dmz'.

