package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
)

func mockPritunlHandler(u []User) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)

		if vars["org_id"] != _pOrgId || r.Header.Get("Auth-Token") != _pToken ||
			r.Header.Get("Auth-Timestamp") == "" || r.Header.Get("Auth-Nonce") == "" ||
			r.Header.Get("Auth-Signature") == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}

		resp, _ := json.Marshal(&u)

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(resp); err != nil {
			log.Printf("response-write-error: %+v", err)
		}
	})
}

var (
	_pToken  = uuid.NewV4().String()
	_pSecret = uuid.NewV4().String()
	_pOrgId  = uuid.NewV4().String()
)

func PritunlMockServer(u []User) *httptest.Server {
	mx := mux.NewRouter()
	mx.Handle("/user/{org_id}", mockPritunlHandler(u))
	pServer := httptest.NewServer(mx)

	// run mock pritunl server
	// set env values
	_ = os.Setenv("PRITUNL_TOKEN", _pToken)
	_ = os.Setenv("PRITUNL_SECRET", _pSecret)
	_ = os.Setenv("PRITUNL_ORG_ID", _pOrgId)
	_ = os.Setenv("PRITUNL_HOST", pServer.URL)

	return pServer
}
