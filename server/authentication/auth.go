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
	"go.mongodb.org/mongo-driver/bson"
)

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

var AuthRouter *chi.Mux

func registerUser(resp http.ResponseWriter, req *http.Request) {
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
	hmacEnc.Write([]byte(user.Password))
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

//Login Controller
//read the request username and password
//Find the user associated w username
//Hash the given password and compare against truth

func loginUser(resp http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Content-Type") != "application/json" {
		resp.WriteHeader(400)
		resp.Write([]byte("400 Bad Request"))
		return
	}

	//read in the raw request body
	//deseralize it into a user struct
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

	coll := database.Database.Collection("users")
	var dbUser User
	filter := bson.D{{"username", user.Username}}
	err = coll.FindOne(context.TODO(), filter).Decode(&dbUser)
	if err != nil {
		resp.WriteHeader(404)
		resp.Write([]byte("404 Not Found"))
		return
	}

	key := []byte(os.Getenv("SECRET_KEY"))
	hmacEnc := hmac.New(sha256.New, key)
	hmacEnc.Write([]byte(user.Password))
	hashedPassword := hex.EncodeToString(hmacEnc.Sum(nil))

	if hashedPassword != dbUser.Password {
		resp.WriteHeader(401)
		resp.Write([]byte("401 Unauthorized"))
		return
	}

	resp.Write([]byte("OK"))
}

func init() {
	AuthRouter = chi.NewRouter()
	AuthRouter.Post("/register", registerUser)
	AuthRouter.Post("/login", loginUser)
}
