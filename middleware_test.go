package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/stretchr/testify/assert"

	"github.com/gorilla/mux"
)

func TestAuthorize(t *testing.T) {
	_ = os.Setenv("AUTH_CONFIG", "auth/testdata/rules.json")
	_ = os.Setenv("OTP_SEED", "auth/testdata/pritunl_data.json")

	// Run mock server with middleware attached
	m := mux.NewRouter()
	m.PathPrefix("/").Handler(authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"path": r.URL.Path,
		}

		respBytes, _ := json.Marshal(&resp)
		_, _ = w.Write(respBytes)
	}))).Methods(http.MethodGet)

	m.Handle("/upload", authorize(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"path": r.URL.Path,
		}

		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			resp["error"] = err.Error()
		} else {
			resp["req_body"] = string(reqBody)
		}

		respBytes, _ := json.Marshal(&resp)
		_, _ = w.Write(respBytes)
	}))).Methods(http.MethodPost)

	server := httptest.NewServer(m)

	// Test for various cases
	t.Run("fail upload for non configured path", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/upload", bytes.NewBuffer([]byte("upload_request")))
		assert.Nil(t, err)
		req.Header.Set("X-Project-Name", "missing")
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("fail upload for configured path but invalid", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/upload", bytes.NewBuffer([]byte("upload_request")))
		assert.Nil(t, err)
		req.Header.Set("X-Project-Name", "test")
		req.SetBasicAuth("xyz@trustingsocial.com", "12345")
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("pass upload for configured path with valid credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/upload", bytes.NewBuffer([]byte("upload_request")))
		assert.Nil(t, err)
		req.Header.Set("X-Project-Name", "test")
		otp, _ := totp.GenerateCode("7VP7X6OC37YVIRVI", time.Now())
		req.SetBasicAuth("xyz@trustingsocial.com", otp)
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("fail upload for missing path with admin credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/upload", bytes.NewBuffer([]byte("upload_request")))
		assert.Nil(t, err)
		req.Header.Set("X-Project-Name", "missing")
		otp, _ := totp.GenerateCode("GMYDQN3GGVRWIY3CMNQWINLFGE3DQOJUHFRDOM3DHBSWEZDGGVRA", time.Now())
		req.SetBasicAuth("admin@trustingsocial.com", otp)
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("pass upload for configured path with admin credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/upload", bytes.NewBuffer([]byte("upload_request")))
		assert.Nil(t, err)
		req.Header.Set("X-Project-Name", "test")
		otp, _ := totp.GenerateCode("GMYDQN3GGVRWIY3CMNQWINLFGE3DQOJUHFRDOM3DHBSWEZDGGVRA", time.Now())
		req.SetBasicAuth("admin@trustingsocial.com", otp)
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("fail download for missing path with normal credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/missing/hello.go", nil)
		assert.Nil(t, err)
		req.SetBasicAuth("xyz@trustingsocial.com", "12345")
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("fail download for valid path with wrong credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/test/hello.go", nil)
		assert.Nil(t, err)
		req.SetBasicAuth("xyz@trustingsocial.com", "12345")
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("pass download for valid path with valid credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/test/hello.go", nil)
		assert.Nil(t, err)
		otp, _ := totp.GenerateCode("7VP7X6OC37YVIRVI", time.Now())
		req.SetBasicAuth("xyz@trustingsocial.com", otp)
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("pass download for missing path with admin credentials", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/missing/hello.go", nil)
		assert.Nil(t, err)
		otp, _ := totp.GenerateCode("GMYDQN3GGVRWIY3CMNQWINLFGE3DQOJUHFRDOM3DHBSWEZDGGVRA", time.Now())
		req.SetBasicAuth("admin@trustingsocial.com", otp)
		c := http.Client{}
		resp, _ := c.Do(req)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
