package main

import (
	"engine/models"
	"errors"
	"log"
	"net/http"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// This is an example application without frontend for login and access protected API
func main() {
	dsn := "host=db user=test " +
		"password=dncvgua5r3 dbname=test " +
		"port=5432 sslmode=disable TimeZone=Europe/Rome"
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	models.GlobalDB = database
	database.AutoMigrate(&models.Message{}, &models.User{})

	// fmt.Println("Connected to database.")
	// gin.SetMode(gin.ReleaseMode) //uncomment to enable production mode for gin
	r := gin.Default()

	//configuring cors
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AddAllowHeaders("Authorization")

	r.Use(cors.New(config))

	// the jwt middleware, docs can be found at https://github.com/appleboy/gin-jwt
	// this app is mostly based on the example in the jwt repository
	//JWT example uses User.Username as token field, in this app is substituted with ID
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "example jwt gin psql",
		Key:         []byte("choose your secret"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: models.IdentityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(models.User); ok {
				return jwt.MapClaims{
					models.IdentityKey: v.ID,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &models.User{
				ID: uint(claims[models.IdentityKey].(float64)),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals models.LoginUser
			var outputUser models.User

			if err := c.ShouldBindJSON(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}

			res := models.GlobalDB.Table("users").Where("Username = ?", loginVals.Username).First(&outputUser)
			if errors.Is(res.Error, gorm.ErrRecordNotFound) {
				return nil, jwt.ErrFailedAuthentication
			} else {
				if bcrypt.CompareHashAndPassword(outputUser.Passwd, []byte(loginVals.Passwd)) == nil {
					return models.User{
						// Username:  outputUser.Username,
						// LastName:  outputUser.LastName,
						// FirstName: outputUser.FirstName,
						ID: outputUser.ID,
					}, nil
				} else {
					return nil, jwt.ErrFailedAuthentication
				}
			}

		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			var loginVals models.LoginUser
			v := data.(*models.User)

			//search for user if its id (which is a token key) is present, if exists, it should continue with request
			result := database.Table("users").Where("ID = ?", v.ID).First(&loginVals)
			if result.Error == nil {
				return true
			}

			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
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
	r.POST("/signup", models.SignUp) //this route is not protected

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	auth := r.Group("/auth")
	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc()) //this means that route group auth is protected
	{
		auth.GET("/hello", models.HelloHandler) //example protected API
		message := auth.Group("/message")       //nested routes, will result in /auth/message/create etc.
		{
			message.POST("/create", models.CreateMessage)
			message.GET("/read", models.ReadMessage)
		}
	}

	if err := http.ListenAndServe(":3010", r); err != nil {
		log.Fatal(err)
	}
}
