package authentication

import (
	"blubber/database"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/go-chi/chi"
)

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

var AuthRouter *chi.Mux

func registerUser(resp http.ResponseWriter, req *http.Request) {
	// do error checking
	// make sure that data is present in the request body and satisfies requirements
	// then hash the password and persist to db (HMAC)
	if req.Header.Get("Content-Type") != "application/json" {
		resp.WriteHeader(400)
		resp.Write([]byte("400 Bad Request"))
		return
	}

	//deseralize request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		resp.WriteHeader(400)
		resp.Write([]byte("400 Bad Request"))
		return
	}

	var user User
	err = json.Unmarshal(body, &user)
	if err != nil || len(user.Username) == 0 || len(user.Password) == 0 {
		resp.WriteHeader(400)
		resp.Write([]byte("400 Bad Request"))
		return
	}

	//hash password
	key := []byte(os.Getenv("SECRET_KEY"))
	hmacEnc := hmac.New(sha256.New, key)
	hmacEnc.Write(key)
	user.Password = hex.EncodeToString(hmacEnc.Sum(nil))

	//write to db
	coll := database.Database.Collection("users")
	_, err = coll.InsertOne(context.TODO(), user)
	if err != nil {
		resp.WriteHeader(500)
		resp.Write([]byte("500 Internal Server Error"))
		return
	}

	resp.Write([]byte("OK"))

}

func init() {
	AuthRouter = chi.NewRouter()
	AuthRouter.Post("/register", registerUser)
}
