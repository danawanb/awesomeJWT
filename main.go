package main

import (
    "encoding/json"
    "fmt"
    "github.com/golang-jwt/jwt/v4"
    "log"
    "net/http"
    "time"
)

var jwtKey = []byte("my_secret_key")

var users = map[string]string{
    "user1": "password1",
    "user2": "password2",
}

type Credentials struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type Claims struct {
    Username string `json:"username"`
    jwt.RegisteredClaims
}

func Signin(w http.ResponseWriter, r *http.Request) {
    var creds Credentials
    err := json.NewDecoder(r.Body).Decode(&creds)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    expectedPassword, ok := users[creds.Username]

    if !ok || expectedPassword != creds.Password {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    expirationTime := &jwt.NumericDate{time.Now().Add(time.Minute * 15)}

    claims := &Claims{
        Username: creds.Username,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: expirationTime,
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    http.SetCookie(w, &http.Cookie{
        Name:    "user_token",
        Value:   tokenString,
        Expires: expirationTime.Time,
    })

}

func Welcome(w http.ResponseWriter, r *http.Request) {
    c, err := r.Cookie("user_token")
    if err != nil {
        if err == http.ErrNoCookie {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    tknString := c.Value

    claims := &Claims{}

    tkn, err := jwt.ParseWithClaims(tknString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })

    if err != nil {
        if err == jwt.ErrSignatureInvalid {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    if !tkn.Valid {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

func Refresh(w http.ResponseWriter, r *http.Request) {
    c, err := r.Cookie("user_token")

    if err != nil {
        if err == http.ErrNoCookie {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    tknString := c.Value
    claims := &Claims{}
    tkn, err := jwt.ParseWithClaims(tknString, claims, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })

    if err != nil {
        if err == jwt.ErrSignatureInvalid {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if !tkn.Valid {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    expirationTime := &jwt.NumericDate{time.Now().Add(time.Minute * 15)}
    claims.ExpiresAt = expirationTime

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    http.SetCookie(w, &http.Cookie{
        Name:    "user_token",
        Value:   tokenString,
        Expires: expirationTime.Time,
    })

}
func main() {
    http.HandleFunc("/signin", Signin)
    http.HandleFunc("/welcome", Welcome)
    http.HandleFunc("/refresh", Refresh)

    log.Fatal(http.ListenAndServe(":9009", nil))

}
