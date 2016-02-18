# gin-auth
Gin Auth is a simple authentification system for gin. It's easy customizable so you can create your own middleware for it.

## USAGE
```go
import "github.com/nytr0gen/gin-auth"

func main() {
    r := gin.New()
    authEngine, _ := auth.New(auth.Auth{
        Key:          []byte("a very secret key"),
        CookieMaxAge: 60 * 60, // one hour
        CookieName:   "sid",
        LoginRoute:   "/login",
        CheckClaims: func(claims ClaimsType) (valid bool, err error) {
            username, ok := claims["username"].(string)
            return ok && strings.Contains(username, "boss"), nil
        },
    })

    authGroup := r.Group("/", authEngine.Middleware)
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
```


## USAGE API
```go
import "github.com/nytr0gen/gin-auth"

func MiddlewareAPI(a *auth.Auth) gin.HandlerFunc {
    return func(c *gin.Context) {
        var claims ClaimsType
        query, err := c.Query(a.Name)
        if err != nil || query == "" {
            goto FAILED
        }

        claims, err = a.ParseToken(query)
        if err != nil {
            goto FAILED
        }

        if valid, err := a.Validate(claims); err != nil || !valid {
            goto FAILED
        }

        c.Set("user", claims)
        if _, exists := claims["username"]; exists {
            c.Set("username", claims["username"])
        }
        c.Next()

        return

    FAILED:
        c.String(http.StatusOK, `{"error":"failed"}`)
        c.Abort()
    }
}

func main() {
    r := gin.New()
    authEngine, _ := auth.New(auth.Auth{
        Key:          []byte("a very secret key"),
        CookieMaxAge: 60 * 60, // one hour
        CookieName:   "sid",
        LoginRoute:   "/login",
        CheckClaims: func(claims ClaimsType) (valid bool, err error) {
            username, ok := claims["username"].(string)
            return ok && strings.Contains(username, "boss"), nil
        },
    })

    authGroup := r.Group("/", MiddlewareAPI(authEngine))
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

        if token, err := authEngine.GetToken(claims); err != nil {
            goto ERROR
        } else {
            c.String(http.StatusOK, token)
        }

        return

    ERROR:
        c.String(http.StatusExpectationFailed, err.Error())
    })

    r.Run("127.0.0.1:8080")
}
```
