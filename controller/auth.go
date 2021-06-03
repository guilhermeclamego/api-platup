package controller

import (
	"net/http"

	"github.com/guilhermeclamego/api-platup/model"
	"github.com/guilhermeclamego/api-platup/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Auth struct {
	db  *gorm.DB
	jwt service.JWT
}

func NewAuth(db *gorm.DB, jwt service.JWT) Auth {
	return Auth{db: db, jwt: jwt}
}

func (a *Auth) Login(c *gin.Context) {
	var dto struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&dto); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var user model.User

	if err := a.db.Where("username=? AND deleted_at IS NULL", dto.Username).First(&user).Error; err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if !user.CheckPassword(dto.Password) {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	token, err := a.jwt.GenerateToken(user.ID)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, map[string]string{
		"token": token,
	})
}

func (a *Auth) Me(c *gin.Context) {
	user := c.MustGet("user").(*model.User)
	c.JSON(http.StatusOK, user)
}

func (a *Auth) Create(c *gin.Context) {
	var dto struct {
		Name            string          `json:"name"`
		Username        string          `json:"username"`
		Password        string          `json:"password"`
		PasswordConfirm string          `json:"password_confirm"`
		Level           model.UserLevel `json:"level"`
	}

	if err := c.ShouldBindJSON(&dto); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if dto.Level == model.UserRoot {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid level"})
		return
	}

	if dto.Password != dto.PasswordConfirm {
		c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "Invalid password confirmation"})
		return
	}

	user := model.User{
		Name:     dto.Name,
		Username: dto.Username,
		Level:    dto.Level,
	}

	user.SetPassword(dto.Password)

	if err := a.db.Save(&user).Error; err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (a *Auth) Update(c *gin.Context) {
	var dto struct {
		Name            string `json:"name"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		PasswordConfirm string `json:"password_confirm"`
	}

	if err := c.ShouldBindJSON(&dto); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if dto.Password != "" {
		if dto.Password != dto.PasswordConfirm {
			c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "Invalid password confirmation"})
			return
		}
	}

	var user model.User
	if err := a.db.First(&user, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	user.Name = dto.Name

	if dto.Password != "" {
		user.SetPassword(dto.Password)
	}

	if err := a.db.Save(&user).Error; err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (a *Auth) Delete(c *gin.Context) {
	userId := c.Param("id")

	var user model.User
	if err := a.db.First(&user, userId).Error; err != nil {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	if user.Level == model.UserRoot {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "root-level user cannot be deleted"})
		return
	}

	if err := a.db.Delete(&model.User{}, userId).Error; err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}
