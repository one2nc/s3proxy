package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestJWTToken(t *testing.T) {
	expiry := 3
	c = &config{jwtTokenExpiry: fmt.Sprintf("%d", expiry), jwtSecret: "secret"}
	token, err := createToken("hello", "world", int64(expiry))

	t.Run("create token successfully", func(t *testing.T) {
		assert.Nil(t, err)

		to := Token{}
		jt, err := jwt.ParseWithClaims(token, &to, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return "", fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(c.jwtSecret), nil
		})

		assert.Nil(t, err)
		assert.Equal(t, "hello", to.Username)
		assert.Equal(t, "world", to.Password)

		_, ok := jt.Method.(*jwt.SigningMethodHMAC)
		assert.Equal(t, true, ok)
		assert.True(t, jt.Valid)
	})

	t.Run("validate token successfully", func(t *testing.T) {
		to, err := validateJwtToken(token)
		assert.Nil(t, err)

		assert.Equal(t, "hello", to.Username)
		assert.Equal(t, "world", to.Password)
	})

	t.Run("error for expired token", func(t *testing.T) {
		time.Sleep(time.Duration(expiry+1) * time.Second)

		to, err := validateJwtToken(token)
		assert.Nil(t, to)
		assert.NotNil(t, err)
	})
}
