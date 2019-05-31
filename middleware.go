package main

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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
		var otpValidationRequired bool

		if r.Method != http.MethodGet {
			path = r.Header.Get("X-Project-Name")
			allowDefaultPass = false
			otpValidationRequired = true
		} else {
			path = parts[1]
		}

		sourceIP := r.RemoteAddr
		if ip, found := header(r, "X-Forwarded-For"); found {
			sourceIP = ip
		}

		ioWriter := w.(io.Writer)
		writer := &custom{Writer: ioWriter, ResponseWriter: w, status: http.StatusOK}

		proc := time.Now()

		defer func() {
			log.Printf("[%s] %.3f %d %s %s %s %s",
				sourceIP, time.Since(proc).Seconds(),
				writer.status, r.Method, email, path, r.URL)
		}()

		at := r.Header.Get("X-Auth-Token")

		// if X-Auth-Token is passed, validate the token instead of otp
		var vErr error
		if at != "" {
			jt, err := validateJwtToken(at)
			vErr = err

			if jt != nil {
				email = jt.Username
				r = r.WithContext(context.WithValue(r.Context(), "jwt", jt))
			}
		} else {
			// validate OTP
			o := auth.NewPayload(path, r.Method, sourceIP, email, token, otpValidationRequired, allowDefaultPass)
			_, vErr = t.Verify(o)
		}

		if vErr != nil {
			http.Error(writer, vErr.Error(), http.StatusUnauthorized)
			return
		}

		f.ServeHTTP(writer, r)
	})
}
