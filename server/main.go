package main

import (
	"log"
	"net/http"

	"blubber/authentication"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	r := chi.NewRouter()

	//Middleware
	r.Use(middleware.Logger)

	//Routes
	r.Mount("/auth", authentication.AuthRouter)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})
	http.ListenAndServe(":3000", r)
}
