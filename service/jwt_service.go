package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JWT interface {
	GenerateToken(id uint) (string, error)
	ValidateToken(token string) (uint, error)
}

type jwtService struct {
	secretKey []byte
	issuer    string
}

func NewJWTService(secretKey string) JWT {
	return &jwtService{
		secretKey: []byte(secretKey),
		issuer:    "api-platup",
	}
}

type Claim struct {
	Sum uint `json:"sum"`
	jwt.StandardClaims
}

func (s *jwtService) GenerateToken(id uint) (string, error) {
	claim := &Claim{
		id,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
			Issuer:    s.issuer,
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)

	t, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", err
	}

	return t, nil
}

func (s *jwtService) ValidateToken(token string) (uint, error) {
	parsedToken, err := jwt.ParseWithClaims(token, &Claim{}, func(t *jwt.Token) (interface{}, error) {
		if _, isValid := t.Method.(*jwt.SigningMethodHMAC); !isValid {
			return nil, fmt.Errorf("invalid token: %v", token)
		}

		return s.secretKey, nil
	})
	if err != nil {
		return 0, err
	}
	if !parsedToken.Valid {
		return 0, errors.New("invalid token")
	}
	claims, ok := parsedToken.Claims.(*Claim)
	if !ok {
		return 0, fmt.Errorf("invalid claims type: %T", parsedToken.Claims)
	}
	return claims.Sum, nil
}
