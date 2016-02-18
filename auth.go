package auth

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type ClaimsType map[string]interface{}
type CheckClaims func(ClaimsType) (valid bool, err error)

type Auth struct {
	Key          []byte
	CookieName   string
	CookieMaxAge int
	LoginRoute   string
}

func New(params Auth) (*Auth, error) {
	// TODO: validate data
	// key not empty
	// cookie name not empty
	// max age > 0
	// check claims not empty
	// login route not empty

	return &params, nil
}

func (a *Auth) SetCookie(c *gin.Context, user ClaimsType) error {
	token, err := a.GetToken(user)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:   a.CookieName,
		Value:  token,
		MaxAge: a.CookieMaxAge,
	}
	http.SetCookie(c.Writer, &cookie)

	return nil
}

func (a *Auth) UnsetCookie(c *gin.Context) {
	cookie := http.Cookie{
		Name:   a.CookieName,
		Value:  "_",
		MaxAge: -1,
	}
	http.SetCookie(c.Writer, &cookie)
}

func (a *Auth) Middleware(checkClaims CheckClaims) gin.HandlerFunc {
	return func(c *gin.Context) {
		var claims ClaimsType
		cookie, err := c.Request.Cookie(a.CookieName)
		if err != nil || cookie == nil {
			goto FAILED
		}

		claims, err = a.ParseToken(cookie.Value)
		if err != nil {
			goto FAILED
		}

		if valid, err := checkClaims(claims); err != nil || !valid {
			goto FAILED
		}

		c.Set("user", claims)
		if _, exists := claims["username"]; exists {
			c.Set("username", claims["username"])
		}
		c.Next()

		return

	FAILED:
		if err != nil {
			a.UnsetCookie(c)
		}
		c.Redirect(http.StatusSeeOther, a.LoginRoute)
		c.Abort()
	}
}
