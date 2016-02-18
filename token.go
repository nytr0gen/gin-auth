package auth

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

func (a *Auth) Validate(claims ClaimsType) (bool, error) {
	if expFloat, ok := claims["expiration"].(float64); ok {
		exp := time.Unix(int64(expFloat), 0)
		if time.Now().After(exp) {
			return false, errors.New("JWT expired")
		}
	} else {
		return false, errors.New("No valid claim for expiration")
	}

	return a.CheckClaims(claims)
}

func (a *Auth) GetToken(claims ClaimsType) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	for k, v := range claims {
		token.Claims[k] = v
	}
	token.Claims["expiration"] = time.Now().Add(time.Duration(a.CookieMaxAge) * time.Second).Unix()

	return token.SignedString(a.Key)
}

func (a *Auth) ParseToken(tokenString string) (claims ClaimsType, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return a.Key, nil
	})
	if err != nil {
		return
	} else if !token.Valid {
		err = errors.New("invalid token")
		return
	}

	return token.Claims, nil
}
