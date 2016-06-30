package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/dgrijalva/jwt-go.v2"
)

// TODO tests

func init() {
	// initServer()
}

func initServer() {
	r := gin.New()
	authEngine, _ := New(Auth{
		Key:          []byte("a very secret key"),
		CookieMaxAge: 60 * 60, // one hour
		CookieName:   "sid",
		LoginRoute:   "/login",
	})

	authGroup := r.Group("/")
	authGroup.Use(authEngine.Middleware(func(claims ClaimsType) (valid bool, err error) {
		username, ok := claims["username"].(string)
		return ok && strings.Contains(username, "boss"), nil
	}))
	authGroup.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "yay")
	})

	r.GET(authEngine.LoginRoute, func(c *gin.Context) {
		var claims = ClaimsType{}
		var err error
		if username := c.Query("username"); username != "" {
			claims["username"] = username
		} else {
			err = errors.New("no username")
			goto ERROR
		}

		if err := authEngine.SetCookie(c, claims); err != nil {
			goto ERROR
		}

		c.Redirect(http.StatusSeeOther, "/")
		return

	ERROR:
		c.String(http.StatusExpectationFailed, err.Error())
	})

	r.Run("127.0.0.1:8080")
}

func TestJWT(t *testing.T) {
	mySigningKey := []byte("sarmale")

	token := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	token.Claims["foo"] = "bar"
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		t.Fatal(err)
		return
	}

	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return mySigningKey, nil
	})

	if err == nil && token.Valid {
		// t.Log("cool")
	} else {
		t.Fatal(":(")
	}
}
