package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/tsocial/s3proxy/auth"
)

func authorize(f http.Handler) http.Handler {
	configPath := os.Getenv("AUTH_CONFIG")
	if configPath == "" {
		panic("AUTH_CONFIG env is not set")
	}

	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic("cannot read AUTH_CONFIG file")
	}

	otpSeedPath := os.Getenv("OTP_SEED")
	if otpSeedPath == "" {
		panic("OTP_SEED env is not set")
	}

	if err := auth.SeedData(otpSeedPath); err != nil {
		panic(err)
	}

	var c auth.RulesConf

	if err := json.Unmarshal(configBytes, &c); err != nil {
		panic("cannot unmarshal AUTH_CONFIG")
	}

	t := auth.New(&c)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, token, _ := r.BasicAuth()
		parts := strings.Split(r.URL.Path, "/")

		var path string
		allowDefaultPass := true
		if r.Method != http.MethodGet {
			path = r.Header.Get("X-Project-Name")
			allowDefaultPass = false
		} else {
			path = parts[1]
		}

		sourceIP := r.RemoteAddr
		if ip, found := header(r, "X-Forwarded-For"); found {
			sourceIP = ip
		}

		o := auth.NewPayload(path, r.Method, sourceIP, email, token, allowDefaultPass)

		if valid, err := t.Verify(o); !valid {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		f.ServeHTTP(w, r)
	})
}
