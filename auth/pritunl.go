package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	url2 "net/url"
	"os"
	"strings"
	"time"

	"github.com/sethgrid/pester"

	uuid "github.com/satori/go.uuid"
)

const MaxRetries = 5

const (
	pToken  = "PRITUNL_TOKEN"
	pSecret = "PRITUNL_SECRET"
	pOrgId  = "PRITUNL_ORG_ID"
	pHost   = "PRITUNL_HOST"
)

func fetchPritunlData() ([]User, error) {
	token := os.Getenv(pToken)
	secret := os.Getenv(pSecret)
	orgId := os.Getenv(pOrgId)
	host := os.Getenv(pHost)

	if token == "" || secret == "" || orgId == "" || host == "" {
		return nil, fmt.Errorf("missing %s or %s or %s or %s", pToken, pSecret, pOrgId, pHost)
	}

	pTimestamp := fmt.Sprintf("%d", time.Now().Unix())
	pAuthNonce := strings.ReplaceAll(uuid.NewV4().String(), "-", "")
	method := http.MethodGet
	path := fmt.Sprintf("/user/%s", orgId)
	pAuthStr := strings.Join([]string{token, pTimestamp, pAuthNonce, method,
		path}, "&")

	// base64.b64encode(hmac.new(API_SECRET, auth_string, hashlib.sha256).digest())
	hm := hmac.New(sha256.New, []byte(secret))
	if _, err := hm.Write([]byte(pAuthStr)); err != nil {
		return nil, err
	}

	pAuthSignature := base64.StdEncoding.EncodeToString(hm.Sum(nil))

	headers := map[string]string{
		"Auth-Token":     token,
		"Auth-Timestamp": pTimestamp,
		"Auth-Nonce":     pAuthNonce,
		"Auth-Signature": pAuthSignature,
	}

	c := pester.New()
	c.MaxRetries = MaxRetries
	c.Backoff = pester.ExponentialBackoff
	c.Timeout = 60 * time.Second

	url, err := url2.Parse(host + path)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url.String(), nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	rsp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := rsp.Body.Close(); err != nil {
			log.Printf("response-body-close-error: %+v", err)
		}
	}()

	rspBody, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	var users []User

	if err := json.Unmarshal(rspBody, &users); err != nil {
		return nil, err
	}

	return users, nil
}

func ExportPritunlConfig() {
	data, err := fetchPritunlData()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	uBytes, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	fmt.Println(string(uBytes))
}
