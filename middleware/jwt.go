package middleware

import (
	"net/http"
	"time"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/errno"
	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/log"

	"github.com/gin-gonic/gin"

	"github.com/WeixinCloud/wxcloudrun-wxcomponent/comm/utils"
)

var ipWhiteList = map[string]bool{
	"172.81.205.253": true,
}

// JWTMiddleWare 中间件
func JWTMiddleWare(c *gin.Context) {
	reqIP := c.ClientIP()
	log.Debugf("reqIP>>>[%s]", reqIP)
	if _, ok := ipWhiteList[reqIP]; ok {
		log.Debugf("ip-whitelist")
		c.Next()
		return
	}
	code := errno.OK
	strToken := c.Request.Header.Get("Authorization")
	token := utils.GetToken(strToken)
	log.Debugf("jwt[%s]", token)

	var err error
	var claims *utils.Claims

	if token == "" {
		code = errno.ErrNotAuthorized
	} else {
		claims, err = utils.ParseToken(token)
		if err != nil {
			code = errno.ErrAuthTokenErr
		} else if time.Now().Unix() > claims.ExpiresAt.Unix() {
			code = errno.ErrAuthTimeout
		}
	}

	if code != errno.OK {
		c.JSON(http.StatusOK, code)
		c.Abort()
		return
	}

	log.Debugf("id:%s UserName:%s", claims.ID, claims.UserName)

	c.Set("jwt", claims)

	c.Next()
}
