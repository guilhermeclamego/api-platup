package model

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserLevel uint8

const (
	UserRoot UserLevel = iota
	UserManager
	UserCommon
)

type User struct {
	ID        uint           `json:"-" gorm:"primaryKey"`
	Name      string         `json:"name"`
	Username  string         `json:"username"`
	Password  string         `json:"-"`
	Level     UserLevel      `json:"level"`
	CreatedAt time.Time      `json:"-"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `json:"-"`
}

// SetPassword set password
func (u *User) SetPassword(password string) error {
	if password == "" {
		return fmt.Errorf("Invalid password")
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	u.Password = string(hashedPassword)

	return nil
}

// CheckPassword compare password
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}
