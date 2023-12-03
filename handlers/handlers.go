package handlers

import (
	"encoding/json"
	"fmt"
	"golang/auth"
	"golang/middleware"
	"golang/models"
	"golang/service"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

var tkn struct {
	Token string `json:"token"`
}

var OTP int

type handler struct {
	db *service.Conn
	a  *auth.Auth
	m  *middleware.Mid
}

func (h *handler) Signup(c *gin.Context) {
	ctx := c.Request.Context()
	traceId, ok := ctx.Value(middleware.TrackerIdKey).(string)
	if !ok {
		log.Error().Msg("traceId missing from context")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "Track Id missing"})
		return
	}

	var nu models.NewUserReq
	body := c.Request.Body
	err := json.NewDecoder(body).Decode(&nu)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("Problem in reading request body for new user")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "Invalid JSON format for new user"})
	}

	validate := validator.New()
	err = validate.Struct(nu)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("please provide name, email and password.")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "Validation failed"})
		return
	}

	err = h.db.AutoMigrate()
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("check handler")
	}

	newRecord, err := h.db.CreateUser(nu)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("check handler")
	}

	log.Info().Str("user_name", newRecord.Name).Str("Trace Id", traceId).Msg("User created successfully")
	c.JSON(http.StatusOK, newRecord)

}

func (h *handler) Login(c *gin.Context) {
	ctx := c.Request.Context()
	traceId, ok := ctx.Value(middleware.TrackerIdKey).(string)
	if !ok {
		log.Error().Msg("traceId missing from context")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "Track Id missing"})
	}

	var user models.LoginReq
	credit := c.Request.Body
	err := json.NewDecoder(credit).Decode(&user)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("Problem in reading request body for login")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "Invalid JSON format for for login"})
	}

	validate := validator.New()
	err = validate.Struct(user)
	if err != nil {
		log.Error().Err(err).Msg("please provide all credentials, Name and Password")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "Validation failed, please provide all credentials"})
	}

	// Generate a new token and put it in the Token field of the token struct
	// Define a new struct for the token

	claims, err := h.db.UserAuthentication(user)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("password didn't match: handler layer")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "Authentication failed, check user and password or registered claims,"})
		return
	}
	tkn.Token, err = h.a.GenerateToken(claims)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("generating token")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "error in token generation"})
		return
	}

	log.Info().Str("user_name", user.Email).Msg("Login successfully...")
	c.JSON(http.StatusOK, gin.H{"Msg": "Login Succesfull..."})
	c.JSON(http.StatusOK, tkn)

}

func (h *handler) AddBreed(c *gin.Context) {
	ctx := c.Request.Context()
	traceId, ok := ctx.Value(middleware.TrackerIdKey).(string)
	if !ok {
		log.Error().Msg("traceId missing from context")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "Track Id missing"})
		return
	}

	var newBreed models.NewBreedReq
	body := c.Request.Body
	err := json.NewDecoder(body).Decode(&newBreed)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("problem in reading request body for new breed")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "Invalid JSON format for new user"})
	}

	validate := validator.New()
	err = validate.Struct(newBreed)
	if err != nil {
		log.Error().Err(err).Msg("please provide all credentials, Name and Password")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "Validation failed, please provide all credentials"})
	}

	err = h.db.AutoMigrate()
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("check handler")
	}

	newRecord, err := h.db.CreateBreed(newBreed)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("check handler")
	}

	log.Info().Str("Cat Name : ", newRecord.Name).Str("Trace Id", traceId).Msg("New Breed record created successfully")
	c.JSON(http.StatusOK, newRecord)

}

func (h *handler) ViewAllBreeds(c *gin.Context) {
	ctx := c.Request.Context()
	traceId, ok := ctx.Value(middleware.TrackerIdKey).(string)
	if !ok {
		log.Error().Msg("traceId missing from context")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "Track Id missing"})
		return
	}

	catBreeds, err := h.db.ViewCatBreeds()
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("check handler")
	}

	log.Info().Str("Trace Id", traceId).Msg("All Cat Breeds info:")
	c.JSON(http.StatusOK, catBreeds)
}

func (h *handler) ForgotPassword(c *gin.Context) {
	ctx := c.Request.Context()
	traceId, ok := ctx.Value(middleware.TrackerIdKey).(string)
	if !ok {
		log.Error().Msg("traceId missing from context")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "Track Id missing"})
	}

	var resetPassword models.ResetPasswordReq
	credit := c.Request.Body
	err := json.NewDecoder(credit).Decode(&resetPassword)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("Problem in reading request body for login")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "Invalid JSON format for for login"})
	}

	validate := validator.New()
	err = validate.Struct(resetPassword)
	if err != nil {
		log.Error().Err(err).Msg("validation fail, please provide, email and date of birth in json format")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "Validation failed, please provide email and date of birth in json format"})
	}

	user, err := h.db.UserExist(resetPassword)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("check handler")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "User not exist..."})
		return
	}

	log.Info().Str("Trace Id", traceId).Msg("User Exist:")
	c.JSON(http.StatusOK, gin.H{"msg": "User Exist..."})
	c.JSON(http.StatusOK, user)

	OTP, err = h.db.GenerateAndSendOTP(resetPassword)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("check handler")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "otp generation error..."})
		return
	}

	log.Info().Str("Trace Id", traceId).Msgf("OTP Generated: %06d", OTP)
	c.JSON(http.StatusOK, gin.H{"msg": "User Exist..."})
	c.JSON(http.StatusOK, gin.H{
		"message": "OTP Generated",
		"otp":     fmt.Sprintf("%06d", OTP),
	})

}

func (h *handler) ResetPassword(c *gin.Context) {
	ctx := c.Request.Context()
	traceId, ok := ctx.Value(middleware.TrackerIdKey).(string)
	if !ok {
		log.Error().Msg("traceId missing from context")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "Track Id missing"})
	}

	var newPassword models.NewPasswordReq
	credit := c.Request.Body
	err := json.NewDecoder(credit).Decode(&newPassword)
	if err != nil {
		log.Error().Err(err).Str("Trace Id", traceId).Msg("Problem in reading request body for login")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "Invalid JSON format for for login"})
	}

	validate := validator.New()
	err = validate.Struct(newPassword)
	if err != nil {
		log.Error().Err(err).Msg("validation fail, please provide, email and date of birth in json format")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "Validation failed, please provide email and date of birth in json format"})
	}
	fmt.Println(OTP)
	err = h.db.VerifyOTP(newPassword, OTP)
	if err != nil {
		log.Error().Err(err).Msg("OTP varificaiton fails...")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "OTP didn't matched..."})
		return
	}

	updateField, err := h.db.UpdatePassword(newPassword)
	if err != nil {
		log.Error().Err(err).Msg("update password fails")
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"msg": "Update password fails..."})
		return
	}

	log.Info().Str("Trace Id", traceId).Msg("Password updated")
	c.JSON(http.StatusOK, gin.H{"msg": "Password Updated..."})
	c.JSON(http.StatusOK, updateField)

}

func check(c *gin.Context) {
	time.Sleep(time.Second * 3)
	select {
	case <-c.Request.Context().Done():
		fmt.Println("user not there")
		return
	default:
		c.JSON(http.StatusOK, gin.H{"msg": "statusOk"})
		c.JSON(http.StatusOK, tkn)
	}
}

func API(db *gorm.DB, a *auth.Auth, m *middleware.Mid) *gin.Engine {
	db_conn, err := service.NewConn(db)
	if err != nil {
		log.Error().Err(err).Msg("check handler")
	}

	h := handler{
		db: db_conn,
		a:  a,
		m:  m,
	}

	// Create a new Gin engine
	r := gin.New()

	// Use the middleware and recovery globally
	r.Use(m.Logger(), gin.Recovery())

	// Define routes
	r.POST("/signup", h.Signup)
	r.POST("/forgotpassword", h.ForgotPassword)
	r.POST("/resetpassword", h.ResetPassword)
	r.POST("/login", h.Login)
	r.GET("/check", m.Authenticate(check))
	r.POST("/add/breed", m.Authenticate(h.AddBreed))
	r.GET("/view/breeds", m.Authenticate(h.ViewAllBreeds))

	return r
}
