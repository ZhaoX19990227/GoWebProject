package controller

import (
	"bluebell_backend/dao/mysql"
	"bluebell_backend/logic"
	"bluebell_backend/models"
	"bluebell_backend/pkg/jwt"
	"fmt"
	"github.com/go-playground/validator/v10"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SignUpHandler 注册业务
func SignUpHandler(c *gin.Context) {
	// 1.获取请求参数
	var fo *models.RegisterForm
	// 2.校验数据有效性
	if err := c.ShouldBindJSON(&fo); err != nil {
		// 请求参数有误，直接返回响应
		zap.L().Error("SignUp with invalid param", zap.Error(err))
		// 判断err是不是 validator.ValidationErrors类型的errors
		errs, ok := err.(validator.ValidationErrors)
		if !ok {
			// 非validator.ValidationErrors类型错误直接返回
			ResponseError(c, CodeInvalidParams) // 请求参数错误
			return
		}
		// validator.ValidationErrors类型错误则进行翻译
		ResponseErrorWithMsg(c, CodeInvalidParams, removeTopStruct(errs.Translate(trans)))
		return // 翻译错误
	}
	fmt.Printf("fo: %v\n", fo)
	// 3.业务处理 —— 注册用户
	if err := logic.SignUp(fo); err != nil {
		zap.L().Error("logic.signup failed", zap.Error(err))
		if err.Error() == mysql.ErrorUserExit {
			ResponseError(c, CodeUserExist)
			return
		}
		ResponseError(c, CodeServerBusy)
		return
	}
	//返回响应
	ResponseSuccess(c, nil)
}

// LoginHandler 登录业务
func LoginHandler(c *gin.Context) {
	// 1、获取请求参数及参数校验
	var u *models.LoginForm
	if err := c.ShouldBindJSON(&u); err != nil {
		// 请求参数有误，直接返回响应
		// zap: 这是一个日志记录库，通常用于Go语言的应用程序。
		// L(): L函数用于创建或获取一个Logger实例，用于记录日志
		zap.L().Error("Login with invalid param", zap.Error(err))

		//将err变量尝试转换为validator.ValidationErrors类型，如果转换成功，将错误值存储在errs变量中，并将ok标志设置为true。
		//如果转换失败，errs将持有validator.ValidationErrors类型的零值（nil），并将ok标志设置为false。
		errs, ok := err.(validator.ValidationErrors)
		if !ok {
			// 非validator.ValidationErrors类型错误直接返回
			ResponseError(c, CodeInvalidParams) // 请求参数错误
			return
		}
		// validator.ValidationErrors类型错误则进行翻译
		// removeTopStruct(): 这可能是一个函数调用，用于从错误信息中移除顶层结构的操作。有时，当使用验证器（validator）进行参数验证时
		// 错误信息可能会包含一些额外的结构信息，这些信息可能不太需要暴露给终端用户，因此可能需要将其从错误信息中剥离。
		ResponseErrorWithMsg(c, CodeInvalidParams, removeTopStruct(errs.Translate(trans)))
		return
	}

	// 2、业务逻辑处理——登录
	user, err := logic.Login(u)
	if err != nil {
		zap.L().Error("logic.Login failed", zap.String("username", u.UserName), zap.Error(err))
		if err.Error() == mysql.ErrorUserNotExit {
			ResponseError(c, CodeUserNotExist)
			return
		}
		ResponseError(c, CodeInvalidParams)
		return
	}
	// 3、返回响应
	ResponseSuccess(c, gin.H{
		"user_id":       fmt.Sprintf("%d", user.UserID), //js识别的最大值：id值大于1<<53-1  int64: i<<63-1
		"user_name":     user.UserName,
		"access_token":  user.AccessToken,
		"refresh_token": user.RefreshToken,
	})
}

// RefreshTokenHandler 刷新accessToken
func RefreshTokenHandler(c *gin.Context) {
	rt := c.Query("refresh_token")
	// 客户端携带Token有三种方式 1.放在请求头 2.放在请求体 3.放在URI
	// 这里假设Token放在Header的 Authorization 中，并使用 Bearer 开头
	// 这里的具体实现方式要依据你的实际业务情况决定
	authHeader := c.Request.Header.Get("Authorization")
	if authHeader == "" {
		ResponseErrorWithMsg(c, CodeInvalidToken, "请求头缺少Auth Token")
		c.Abort()
		return
	}
	// 按空格分割
	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		ResponseErrorWithMsg(c, CodeInvalidToken, "Token格式不对")
		c.Abort()
		return
	}
	aToken, rToken, err := jwt.RefreshToken(parts[1], rt)
	zap.L().Error("jwt.RefreshToken failed", zap.Error(err))
	c.JSON(http.StatusOK, gin.H{
		"access_token":  aToken,
		"refresh_token": rToken,
	})
}
