package main

import (
	"testing"
	"time"

	"fmt"

	"github.com/dgrijalva/jwt-go"
)

func TestJWTToken(t *testing.T) {
	c = &config{jwtTokenExpiry: "3", jwtSecret: "secret"}
	token, err := createToken("johndoe", "password", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	p, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(c.jwtSecret), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("should validate username and password", func(t *testing.T) {
		claims, ok := p.Claims.(jwt.MapClaims)
		if !ok && !p.Valid {
			t.Fatal("token is invalid")
		}

		if claims["expiry"].(float64) < float64(time.Now().Unix()) {
			t.Fatal("should have passed")
		}

		if claims["username"] != "johndoe" || claims["password"] != "password" {
			t.Fatal("username, password doesn't match")
		}
	})

	t.Run("should fail for expiry of token", func(t *testing.T) {
		time.Sleep(time.Second * 3)

		if claims, ok := p.Claims.(jwt.MapClaims); ok && p.Valid {
			if claims["expiry"].(float64) > float64(time.Now().Unix()) {
				t.Fatal("should have failed")
			}
		}
	})
}
