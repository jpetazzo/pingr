package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/discordianfish/go-collins/collins"

	_ "net/http/pprof"
)

const samplePath = "/int/tcp/22/server_node/primary_role;web/secondary_role;default"

var (
	client   *collins.Client
	listen   = flag.String("listen", "0.0.0.0:8000", "adress to listen on")
	authUser = flag.String("auth.user", "ping", "user for basic auth")
	authPass = flag.String("auth.pass", "", "password for basic auth")

	user = flag.String("user", "blake", "collins username")
	pass = flag.String("pass", "admin:first", "collins password")
	cUrl = flag.String("url", "http://localhost:9000/api", "collins api url")

	assetStatus       = flag.String("status", "Allocated", "only assets with this status")
	connectionTimeout = flag.Duration("", 5*time.Second, "connect timeout for tests")
	readWriteTimeout  = flag.Duration("timeout", 5*time.Second, "rw timeout for tests")

	authHeaderInvalid      = errors.New("Invalid Authorization header")
	authCredentialsInvalid = errors.New("Invalid user or password")
)

type status struct {
	asset collins.AssetDetails
	err   error
}

func handleError(w http.ResponseWriter, msg string) {
	log.Println(msg)
	http.Error(w, msg, http.StatusInternalServerError)
}

func ping(tUrl *url.URL) error {
	switch tUrl.Scheme {
	case "http":
		return pingHttp(tUrl)
	case "tcp":
		return pingTcp(tUrl)
	default:
		return fmt.Errorf("Scheme %s not supported", tUrl.Scheme)
	}
}

func pingTcp(tUrl *url.URL) error {
	conn, err := net.DialTimeout(tUrl.Scheme, tUrl.Host, *connectionTimeout)
	if err != nil {
		return err
	}
	// If a path was specified, look for it in the TCP connection output.
	if tUrl.Path != "" {
		conn.SetDeadline(time.Now().Add(*readWriteTimeout))
		accum := ""
		// There is no exit condition, because conn.Read will eventually timeout.
		for {
			buffer := make([]byte, 512)
			n, err := conn.Read(buffer)
			if err != nil {
				return err
			}
			accum += string(buffer[:n])
			if strings.Contains(accum, tUrl.Path) {
				return nil
			}
		}
	}
	return conn.Close()
}

func pingHttp(tUrl *url.URL) error {
	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(n, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(n, addr, *connectionTimeout)
				if err != nil {
					return nil, err
				}
				conn.SetDeadline(time.Now().Add(*readWriteTimeout))
				return conn, nil
			},
		},
	}
	resp, err := client.Get(tUrl.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Error %d (%s): %s", resp.StatusCode, resp.Status, err)
		}
		if len(body) == 0 {
			return fmt.Errorf("Error %d (%s)", resp.StatusCode, resp.Status)
		}
		return fmt.Errorf("Error %d (%s): %s", resp.StatusCode, resp.Status, body)
	}
	return nil
}

func isAlive(tag, tType string, port int, pool, path string) error {
	addresses, err := client.GetAssetAddresses(tag)
	if err != nil {
		return fmt.Errorf("[collins failed] %s", err)
	}
	tUrl := &url.URL{
		Scheme: tType,
		Path:   path,
	}
	urls := []*url.URL{}
	for _, address := range addresses.Data.Addresses {
		if pool != strings.ToLower(address.Pool) {
			continue
		}
		tUrl.Host = fmt.Sprintf("%s:%d", address.Address, port)
		urls = append(urls, tUrl)
	}

	errChan := make(chan error, len(urls))
	defer close(errChan)
	for _, tUrl := range urls {
		go func(tUrl *url.URL) {
			errChan <- ping(tUrl)
		}(tUrl)
	}

	statuses := []string{}
	for i := 0; i < cap(errChan); i++ {
		err := <-errChan
		if err != nil {
			statuses = append(statuses, err.Error())
		}
	}
	if len(statuses) > 0 {
		return errors.New(strings.Join(statuses, ", "))
	}
	return nil

}

func isAuth(r *http.Request) error {
	parts := strings.Split(r.Header["Authorization"][0], " ")
	if len(parts) != 2 || parts[0] != "Basic" {
		return authHeaderInvalid
	}
	auth := parts[1]
	log.Printf("auth header: %s", auth)
	authStr, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return err
	}
	parts = strings.Split(string(authStr), ":")
	if len(parts) != 2 {
		return authHeaderInvalid
	}
	if parts[0] != *authUser || parts[1] != *authPass {
		return authCredentialsInvalid
	}
	return nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("< %s", r.URL)
	if *authPass != "" {
		if len(r.Header["Authorization"]) == 0 {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"ping\"")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if err := isAuth(r); err != nil {
			m := fmt.Sprintf("[auth] %s", err)
			http.Error(w, m, http.StatusUnauthorized)
			return
		}
	}

	path := strings.Split(r.URL.Path[1:], "/")
	if len(path) < 4 {
		handleError(w, fmt.Sprintf("Invalid path: %s\nTry: %s", r.URL.Path[1:], samplePath))
		return
	}

	pool := path[0]
	tType := path[1]
	portS := path[2]
	aType := path[3]
	tPath := ""
	if len(path) > 4 {
		tPath = strings.Join(path[4:], "/")
	}

	params := &url.Values{}
	attributes, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		handleError(w, fmt.Sprintf("Invalid attributes: %s", err))
		return
	}
	for k, as := range attributes {
		params.Add("attribute", fmt.Sprintf("%s;%s", k, as[0]))
	}

	port, err := strconv.Atoi(portS)
	if err != nil {
		handleError(w, fmt.Sprintf("Invalid port '%s' in path", portS))
		return
	}

	params.Set("type", aType)
	if params.Get("status") == "" {
		params.Set("status", *assetStatus)
	}
	assets, err := client.FindAssets(params)
	if err != nil {
		handleError(w, fmt.Sprintf("[collins unreachable] %s", err))
		return
	}

	statusChan := make(chan status, len(assets.Data.Data))
	defer close(statusChan)
	for _, asset := range assets.Data.Data {
		go func(asset collins.AssetDetails) {
			statusChan <- status{
				asset: asset,
				err:   isAlive(asset.Asset.Tag, tType, port, pool, tPath),
			}
		}(asset)
	}

	errors := false
	msgs := ""
	for i := 0; i < cap(statusChan); i++ {
		t := "Alive"
		status := <-statusChan
		if status.err != nil {
			errors = true
			t = status.err.Error()
		}
		msg := fmt.Sprintf("[%s] %s", status.asset.Asset.Tag, t)
		msgs = fmt.Sprintf("%s%s\n", msgs, msg)
		log.Println(msg)
	}

	if errors {
		handleError(w, msgs)
	} else {
		fmt.Fprint(w, msgs)
	}
}

func main() {
	flag.Parse()
	client = collins.New(*user, *pass, *cUrl)

	http.HandleFunc("/", handler)
	log.Printf("Listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
