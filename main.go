package main

import (
	"github.com/guilhermeclamego/api-platup/controller"
	"github.com/guilhermeclamego/api-platup/model"
	"github.com/guilhermeclamego/api-platup/route/middleware"
	"github.com/guilhermeclamego/api-platup/service"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("plataforma.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err := createSuperUser(db); err != nil {
		panic(err)
	}

	db.AutoMigrate(&model.User{})

	jwtService := service.NewJWTService("lHMZ3XtB4E7M2XEXlp81R8Pm8IQmU8rrcZoH4Bzfo0dQq2nswUttpsblGSVh1lAXDDDpRYXDVVoU8W1u5kx2zilDsb6hoTsXErrfIbvRtXC6Ps5TxqZshFWfsfuA03zx")
	auth := controller.NewAuth(db, jwtService)

	userRoot := middleware.UserLevel(model.UserRoot)
	// userManager := middleware.UserLevel(model.UserManager)
	// userCommon := middleware.UserLevel(model.UserCommon)

	app := gin.Default()
	app.POST("/login", auth.Login)

	{
		api := app.Group("/api", middleware.Auth(db, jwtService))

		api.GET("me", auth.Me)
		api.POST("user", userRoot, auth.Create)
		api.PUT("user/:id", userRoot, auth.Update)
		api.DELETE("user/:id", userRoot, auth.Delete)
	}

	app.Run(":3000")
}

func createSuperUser(db *gorm.DB) error {
	var count int64

	if db.Model(model.User{}).Count(&count).Error != nil {

	}

	if count > 0 {
		return nil
	}

	user := model.User{
		Name:     "Super User",
		Username: "su",
		Level:    model.UserRoot,
	}

	user.SetPassword("123")

	db.Save(&user)

	return nil
}
