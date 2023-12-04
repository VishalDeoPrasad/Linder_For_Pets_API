package models

type ForgotPasswordReq struct {
	Email string `json:"email" validate:"required"`
	DOB   string `json:"dob" validate:"required"`
}

type NewPasswordReq struct {
	Email           string `json:"email" validate:"required"`
	DOB             string `json:"dob" validate:"required"`
	OTP             int    `json:"otp" validate:"required"`
	NewPassword     string `json:"newPassword" validate:"required"`
	ConfirmPassword string `json:"confirmPassword" validate:"required"`
}
