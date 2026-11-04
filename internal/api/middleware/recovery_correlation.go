package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/recoverycorrelation"
)

// RecoveryCorrelation consumes diagnostic-only headers before other middleware.
func RecoveryCorrelation() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request = recoverycorrelation.Consume(c.Request)
		c.Next()
	}
}
