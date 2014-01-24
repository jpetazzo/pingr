package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/discordianfish/go-collins/collins"
)

var (
	client *collins.Client
	listen = flag.String("listen", "0.0.0.0:8000", "adress to listen on")

	user = flag.String("user", "blake", "username")
	pass = flag.String("pass", "admin:first", "password")
	cUrl = flag.String("url", "http://localhost:9000/api", "collins api url")

	assetType   = flag.String("type", "SERVER_NODE", "only assets with this type")
	assetStatus = flag.String("status", "Allocated", "only assets with this status")

	connectionTimeout = flag.Duration("", 5*time.Second, "connect timeout for tests")
	readWriteTimeout  = flag.Duration("timeout", 5*time.Second, "rw timeout for tests")
	tests             testUrls
)

type testUrls map[string][]string

func (t testUrls) String() string { return "" }

func (t testUrls) Set(str string) error {
	parts := strings.SplitN(str, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("Couldn't parse %s", str)
	}
	pool := parts[0]
	tUrl := parts[1]
	if t[pool] == nil {
		t[pool] = []string{}
	}
	t[pool] = append(t[pool], tUrl)
	return nil
}

type status struct {
	asset collins.AssetDetails
	err   error
}

func handleError(w http.ResponseWriter, msg string) {
	log.Println(msg)
	http.Error(w, msg, http.StatusInternalServerError)
}

func ping(tUrl string) error {
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
	resp, err := client.Get(tUrl)
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

func isAlive(tag string) error {
	addresses, err := client.GetAssetAddresses(tag)
	if err != nil {
		return fmt.Errorf("[collins failed] %s", err)
	}
	urls := []string{}
	for _, address := range addresses.Data.Addresses {
		pool := strings.ToLower(address.Pool)
		for _, tUrl := range tests[pool] {
			urls = append(urls, fmt.Sprintf(tUrl, address.Address))
		}
	}

	errChan := make(chan error, len(urls))
	defer close(errChan)
	for _, tUrl := range urls {
		go func(tUrl string) { errChan <- ping(tUrl) }(tUrl)
	}

	for i := 0; i < cap(errChan); i++ {
		err := <-errChan
		if err != nil {
			return err
		}
	}
	return nil

}

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[1:]
	log.Printf("< %s", r.URL)
	params := &url.Values{}
	if *assetType != "" {
		params.Set("type", *assetType)
	}
	if *assetStatus != "" {
		params.Set("status", *assetStatus)
	}
	if path != "" {
		params.Set("attribute", path)
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
				err:   isAlive(asset.Asset.Tag),
			}
		}(asset)
	}

	errors := false
	msgs := ""
	for i := 0; i < cap(statusChan); i++ {
		t := "Alive"
		status := <- statusChan
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
	tests = testUrls{}
	flag.Var(tests, "t", "specify urls to test per pool in format pool:url")
	flag.Parse()
	client = collins.New(*user, *pass, *cUrl)

	http.HandleFunc("/", handler)
	log.Printf("Listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}