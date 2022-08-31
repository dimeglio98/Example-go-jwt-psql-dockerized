package main

import (
	"engine/models"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {

	/*
	* gin.SetMode(gin.ReleaseMode) <- per passare in production
	*
	 */
	dsn := "host=db user=test " +
		"password=uc4Utauu dbname=test " +
		"port=5432 sslmode=disable TimeZone=Europe/Rome"
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	models.GlobalDB = database
	database.AutoMigrate(&models.Message{}, &models.User{})

	fmt.Println("Connected to database.")

	port := os.Getenv("PORT")
	r := gin.Default()

	if port == "" {
		port = "3010"
	}

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "example jwt gin psql",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: models.IdentityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			//non so cosa faccia questa funzione, forse aggiunge gli elementi al token
			fmt.Println("PAYLOADFUNC")
			if v, ok := data.(models.User); ok {
				// fmt.Println(data)
				return jwt.MapClaims{
					models.IdentityKey: v.ID,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			//questa funzione penso che legga qualcosa dal token, non ho ben capito
			fmt.Println("IDENTITYHANDLER")
			claims := jwt.ExtractClaims(c)
			fmt.Println(claims)
			return &models.User{
				ID: uint(claims[models.IdentityKey].(float64)),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			fmt.Println("LOGIN")
			//questa è una funzione di login, tutta la logica di login va qua dentro
			//da sostituire "models.User" con "Login" perche è piu sicuro
			var loginVals models.LoginUser
			var outputUser models.User
			if err := c.ShouldBindJSON(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			if result := database.Table("users").Where(&loginVals).First(&outputUser); result.Error != nil {
				return nil, jwt.ErrFailedAuthentication
			}

			return models.User{
				Username:  outputUser.Username,
				LastName:  outputUser.LastName,
				FirstName: outputUser.FirstName,
				ID:        outputUser.ID,
			}, nil

		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			//questa funzione viene chiamata quando viene fatta una richiesta di una risorsa protetta
			//deve controllare se l'elemento (l'id o lo username) passato nel token è corretto
			fmt.Println("AUTHORIZATOR")
			var loginVals models.LoginUser
			v := data.(*models.User) //utente passato nel token?

			result := database.Table("users").Where("ID = ?", v.ID).First(&loginVals)
			if result.Error == nil {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			//funzione che restituisce il messaggio nel caso le credenziali siano errate (token scaduto, pwd errata, ecc)
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		// - "param:<name>"
		TokenLookup: "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",

		// TokenHeadName is a string in the header. Default value is "Bearer"
		TokenHeadName: "Bearer",

		// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
		TimeFunc: time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	// When you use jwt.New(), the function is already automatically called for checking,
	// which means you don't need to call it again.
	errInit := authMiddleware.MiddlewareInit()

	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	r.POST("/login", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	// Refresh time can be longer than token timeout
	// auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		// auth.GET("/hello", helloHandler)
		message := auth.Group("/message")
		{
			message.POST("/create", models.CreateMessage)
			message.GET("/read", models.ReadMessage)
		}
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
