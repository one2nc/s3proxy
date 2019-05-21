package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Token struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ExpireOn int64  `json:"expire_on"`
}

func (t *Token) Valid() error {
	if t.ExpireOn < time.Now().Unix() {
		return errors.New("token expired")
	}

	if t.Username == "" {
		return errors.New("username missing")
	}

	return nil
}

func createToken(username, password string, expiry int64) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, &Token{username, password,
		time.Now().Add(time.Second * time.Duration(expiry)).Unix()})

	return t.SignedString([]byte(c.jwtSecret))
}

func validateJwtToken(t string) (*Token, error) {
	token := Token{}
	jt, err := jwt.ParseWithClaims(t, &token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return "", fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(c.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("jwt-parsing-error: %v", err)
	}

	if !jt.Valid {
		return nil, fmt.Errorf("not authorized: invalid X-Auth-Token")
	}

	return &token, nil
}
