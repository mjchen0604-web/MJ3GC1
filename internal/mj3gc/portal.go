package mj3gc

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type PortalContext struct {
	User User
	Key  *APIKey
}

// PortalAuthMiddleware authenticates portal requests using either Basic auth
// (username/password) or API key headers.
func PortalAuthMiddleware(store *Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "portal unavailable"})
			return
		}

		if user, ok := authenticateBasic(store, c.Request); ok {
			c.Set("portal", PortalContext{User: user})
			c.Next()
			return
		}

		apiKey, ok := authenticateAPIKey(store, c.Request)
		if ok {
			user, _ := store.FindUserByID(apiKey.UserID)
			c.Set("portal", PortalContext{User: user, Key: &apiKey})
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	}
}

func authenticateBasic(store *Store, r *http.Request) (User, bool) {
	if r == nil {
		return User{}, false
	}
	ah := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(ah), "basic ") {
		return User{}, false
	}
	payload := strings.TrimSpace(strings.TrimPrefix(ah, "Basic"))
	payload = strings.TrimSpace(payload)
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return User{}, false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return User{}, false
	}
	user, err := store.AuthenticateUser(parts[0], parts[1])
	if err != nil {
		return User{}, false
	}
	return user, true
}

func authenticateAPIKey(store *Store, r *http.Request) (APIKey, bool) {
	if r == nil {
		return APIKey{}, false
	}
	value, _ := extractKeyFromRequest(r)
	if value == "" {
		return APIKey{}, false
	}
	key, ok := store.FindAPIKey(value)
	if !ok || !key.Enabled {
		return APIKey{}, false
	}
	return key, true
}

func extractKeyFromRequest(r *http.Request) (string, string) {
	ah := r.Header.Get("Authorization")
	if ah != "" {
		parts := strings.SplitN(ah, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1]), "authorization"
		}
		if !strings.HasPrefix(strings.ToLower(ah), "basic ") {
			return strings.TrimSpace(ah), "authorization"
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Api-Key")); v != "" {
		return v, "x-api-key"
	}
	if v := strings.TrimSpace(r.Header.Get("X-Goog-Api-Key")); v != "" {
		return v, "x-goog-api-key"
	}
	if v := strings.TrimSpace(r.Header.Get("X-API-Key")); v != "" {
		return v, "x-api-key"
	}
	if r.URL != nil {
		if v := strings.TrimSpace(r.URL.Query().Get("key")); v != "" {
			return v, "query-key"
		}
		if v := strings.TrimSpace(r.URL.Query().Get("auth_token")); v != "" {
			return v, "query-auth-token"
		}
	}
	return "", ""
}
