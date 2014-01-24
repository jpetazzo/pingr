# pingr

This tool will get a list of assets from [collins](tumblr.github.io/collins/),
send http requests configured by the `-t` flag and return HTTP 500 with a
plain text error message in case any request failed.

It takes the path as collins attribute filter. A request to
`/secondary_role;foobar` will send requests to all assets with the
role `foobar`.


# Usage

    Usage of /tmp/go-build311774514/command-line-arguments/_obj/exe/pingr:
      -=5s: connect timeout for tests
      -listen="0.0.0.0:8000": adress to listen on
      -pass="admin:first": password
      -status="Allocated": only assets with this status
      -t=: specify urls to test per pool in format pool:url
      -timeout=5s: rw timeout for tests
      -type="SERVER_NODE": only assets with this type
      -url="http://localhost:9000/api": collins api url
      -user="blake": username
    exit status 2


# Example

    pingr -t int:http://%s:8080/
