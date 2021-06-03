package middleware

import (
	"net/http"

	"github.com/guilhermeclamego/api-platup/model"
	"github.com/guilhermeclamego/api-platup/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Auth(db *gorm.DB, jwt service.JWT) gin.HandlerFunc {
	return func(c *gin.Context) {
		const Bearer_schema = "Bearer "

		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenStr := header[len(Bearer_schema):]

		userId, err := jwt.ValidateToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}

		var user model.User

		if err := db.First(&user, userId).Error; err != nil {
			c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}

		c.Set("user", &user)

		c.Next()
	}
}

func UserLevel(level model.UserLevel) gin.HandlerFunc {
	return func(c *gin.Context) {
		if user, ok := c.MustGet("user").(*model.User); ok && user.Level <= level {
			c.Next()
			return
		}

		c.AbortWithStatus(http.StatusForbidden)
	}
}
