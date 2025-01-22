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

	"github.com/golang-jwt/jwt/v5"
	"time"
	"fmt"
	"strings"
)

type User struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}

var AuthRouter *chi.Mux
var key = []byte(os.Getenv("SECRET_KEY"))

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
	// key := []byte(os.Getenv("SECRET_KEY"))
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

/**
 * loginUser - Reads in User information, authorizes and authenticates User.
 *
 * @resp - The HTTP response writer used to send the response to the client.
 * @req - The HTTP request containing the incoming data, such as Username and Password.
 *
 * @return: None.
 */
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

	// key := []byte(os.Getenv("SECRET_KEY"))
	hmacEnc := hmac.New(sha256.New, key)
	hmacEnc.Write([]byte(user.Password))
	hashedPassword := hex.EncodeToString(hmacEnc.Sum(nil))

	if hashedPassword != dbUser.Password {
		resp.WriteHeader(401)
		resp.Write([]byte("401 Unauthorized"))
		return
	}

	// now that we have authenticated, we need to create our token 
	tokenString, err := generateToken(user.Username)
	if err != nil {
		resp.WriteHeader(404)
		resp.Write([]byte("404 Not Found"))
		return
	}
	// resp.Write([]byte("OK"))
	resp.Write([]byte(tokenString)) // writing token to response
}

// first, we need to create a function that generates our jwt token with our secret key
// then, when our user logs in, that jwt token will be sent over to the client side
// when our client tries to access a specific page/route again, our server will authorize it by verifying the jwt signature

/**
 * generateToken - Creates a new JWT (Java Web Token).
 *
 * @username: Username of client.
 *
 * @return: Returns the signed token or error.
 */
func generateToken(username string) (string, error) {
	// key := []byte(os.Getenv("SECRET_KEY"))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"exp": jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // temporarily, I just set exp date for a week from today (Jan 28th)
		})

	ss, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return ss, nil
}

/**
 * verifyToken - Verifies that the JWT is valid.
 *
 * @tokenString - The JWT that is being verified.
 *
 * @return: None, unless error.
 */
func verifyToken(tokenString string) (error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Println("Unexpected signing method")
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		fmt.Println("Error parsing token: ", err)
		return err
	}

	if !token.Valid {
		err := fmt.Errorf("invalid token")
    	fmt.Println("Error:", err)
		return fmt.Errorf("invalid token")
	}
	// will need to add more switch cases 

	return nil
}

/**
 * testingHandler - Creates a route that is used to test whether JWT Authentication works as intended. Temporary.
 *
 * @resp - The HTTP response writer used to send the response to the client.
 * @req - The HTTP request containing the incoming data, such as the Authentication Token.
 *
 * @return: None.
 */
func testingHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Content-Type") != "application/json" {
		resp.WriteHeader(400)
		resp.Write([]byte("400 Bad Request"))
		return
	}
	tokenString := req.Header.Get("Authorization");
	// this is lowkey monkeycode, need to figure out
	parts := strings.Split(tokenString, " ")
	token := parts[1]
	if strings.HasPrefix(token, "OK") {
		token = token[2:]
	}
	// fmt.Println("TOKEN STRING: ", token)
	if token == "" {
		resp.WriteHeader(500)
		resp.Write([]byte("500 Internal Server Error"))
		return
	}
	err := verifyToken(token)
	if err != nil {
		resp.WriteHeader(401)
		resp.Write([]byte("401 Unauthorized and token not verified"))
		return
	}

	resp.Write([]byte("Welcome"))
}

func init() {
	AuthRouter = chi.NewRouter()
	AuthRouter.Post("/register", registerUser)
	AuthRouter.Post("/login", loginUser)
	AuthRouter.Get("/testing", testingHandler)
}