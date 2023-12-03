package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang/models"
	"math/big"
	"net/smtp"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Conn struct {
	db *gorm.DB
}

// NewService is the constructor for the Conn struct.
func NewConn(db *gorm.DB) (*Conn, error) {
	if db == nil {
		return nil, errors.New("please provide a valid connection")
	}

	s := &Conn{db: db}
	return s, nil
}

func (c *Conn) AutoMigrate() error {
	err := c.db.AutoMigrate(&models.User{}, &models.Breed{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to perform database migration")
		return err
	}
	return nil
}

func (c *Conn) CreateUser(nu models.NewUserReq) (models.User, error) {
	hashPass, err := bcrypt.GenerateFromPassword([]byte(nu.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("hash password is not generating.")
	}

	u1 := models.User{
		Name:         nu.Name,
		DOB:          nu.DOB,
		Email:        nu.Email,
		PasswordHash: string(hashPass),
	}

	err = c.db.Create(&u1).Error
	if err != nil {
		log.Error().Err(err).Str("user_name", u1.Name).Msg("Failed to create user")
		return u1, err
	}
	return u1, nil
}

func (c *Conn) CreateBreed(nb models.NewBreedReq) (models.Breed, error) {
	newBreed := models.Breed{
		Name:            nb.Name,
		Size:            nb.Size,
		Color:           nb.Color,
		Weight:          nb.Weight,
		EnergyLevel:     nb.EnergyLevel,
		AggressionLevel: nb.AggressionLevel,
	}

	err := c.db.Create(&newBreed).Error
	if err != nil {
		log.Error().Err(err).Str("Cat Breed :", nb.Name).Msg("failed to create new breed")
		return newBreed, err
	}
	return newBreed, nil
}

func (c *Conn) ViewCatBreeds() ([]models.Breed, error) {
	var catBreeds []models.Breed
	result := c.db.Find(&catBreeds)
	if result.Error != nil {
		log.Info().Err(result.Error).Send()
		return nil, errors.New("could not find cats")
	}
	return catBreeds, nil
}

func (c *Conn) UserAuthentication(login models.LoginReq) (jwt.RegisteredClaims, error) {
	email := login.Email
	password := login.Password

	var user models.User
	tx := c.db.Where("email = ?", email).First(&user)
	if tx.Error != nil {
		log.Error().Err(tx.Error).Msg("Email Not Found:")
		return jwt.RegisteredClaims{}, tx.Error
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		log.Error().Err(err).Msg("password didn't match:")
		return jwt.RegisteredClaims{}, err
	}

	// Successful authentication! Generate JWT claims.
	claims := jwt.RegisteredClaims{
		Issuer:    "service project",
		Subject:   strconv.FormatUint(uint64(user.ID), 10),
		Audience:  jwt.ClaimStrings{"students"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	return claims, nil
}

// take the email and dob from request body
// search for check weather email and dob match to database
// if it is matched send otp else don't send otp
func (c *Conn) UserExist(rp models.ResetPasswordReq) (models.User, error) {
	email := rp.Email
	dob := rp.DOB

	var user models.User
	tx := c.db.Where("email = ? AND dob = ?", email, dob).First(&user)
	if tx.Error != nil {
		log.Error().Err(tx.Error).Msg("Email and Date of birth Not Found:")
		return models.User{}, tx.Error
	}
	return user, nil
}

func GenerateOTP() (int, error) {
	max := big.NewInt(999999)
	otp, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("error generating OTP: %w", err)
	}
	return int(otp.Int64()), nil
}

// GenerateAndSendOTP generates an OTP and sends it via email.
func (c *Conn) GenerateAndSendOTP(rp models.ResetPasswordReq) (int, error) {
	// Generate a random OTP
	OTP, err := GenerateOTP()
	if err != nil {
		return 0, err
	}
	// Sender's email address and password
	from := "vishal.prasad2009@gmail.com"
	password := "oxwr hxxl uegs oqyt"

	// Recipient's email address
	to := rp.Email

	// SMTP server details
	smtpServer := "smtp.gmail.com"
	smtpPort := 587

	// Message content with the generated OTP
	message := []byte(fmt.Sprintf("Subject: Your OTP for Password Reset\n\nYour OTP is: %06d", OTP))

	// Authentication information
	auth := smtp.PlainAuth("", from, password, smtpServer)

	// SMTP connection
	smtpAddr := fmt.Sprintf("%s:%d", smtpServer, smtpPort)
	err = smtp.SendMail(smtpAddr, auth, from, []string{to}, message)
	if err != nil {
		log.Error().Err(err).Msg("error in sending email:")
		return 0, err
	}
	fmt.Println("Email sent successfully!")
	return OTP, nil
}

func (c *Conn) VerifyOTP(np models.NewPasswordReq, OTP int) error {
	fmt.Println(np.OTP, OTP)
	if np.OTP != OTP {
		err := errors.New("otp mismatch")
		log.Error().Err(err).Msg("wrong OTP")
		return err
	}
	return nil
}

func (c *Conn) UpdatePassword(np models.NewPasswordReq) (models.User, error) {
	email := np.Email
	dob := np.DOB

	var user models.User
	tx := c.db.Where("email = ? AND dob = ?", email, dob).First(&user)
	if tx.Error != nil {
		log.Error().Err(tx.Error).Msg("Email and Date of birth Not Found:")
		return models.User{}, tx.Error
	}

	if np.ConfirmPassword != np.NewPassword && len(np.ConfirmPassword) > 5 && len(np.NewPassword) > 5 {
		err := errors.New("length of password less then 6 or password mismatch")
		log.Error().Err(err).Msg("check updatepassword() function in service.")
		return models.User{}, err
	}

	hashPass, err := bcrypt.GenerateFromPassword([]byte(np.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("hash password is not generating.")
		return models.User{}, err
	}

	// Update the password
	user.PasswordHash = string(hashPass)
	result := c.db.Save(&user)
	if result.Error != nil {
		return models.User{}, result.Error
	}

	return user, nil
}
