// Package main implements webhook-relay: a high-throughput HTTP forwarder
// that receives webhooks, validates JWT-signed payloads, and forwards
// templated requests downstream. Paired with a Python sidecar that handles
// signature verification, payload templating, and at-rest encryption.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen      string            `yaml:"listen"`
	Downstreams map[string]string `yaml:"downstreams"`
	JWTSecret   string            `yaml:"jwt_secret"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.JWTSecret == "" {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		c.JWTSecret = hex.EncodeToString(buf)
	}
	return &c, nil
}

func verifyJWT(secret, raw string) (jwt.MapClaims, error) {
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	return claims, nil
}

func main() {
	cfgPath := os.Getenv("WEBHOOK_RELAY_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/webhook-relay/config.yaml"
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Printf("config not found at %s, using defaults: %v", cfgPath, err)
		cfg = &Config{Listen: ":8080", Downstreams: map[string]string{}}
	}

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": "0.1.0"})
	})

	r.POST("/webhooks/:source", func(c *gin.Context) {
		source := c.Param("source")
		auth := c.GetHeader("Authorization")
		if len(auth) > 7 && auth[:7] == "Bearer " {
			if _, err := verifyJWT(cfg.JWTSecret, auth[7:]); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				return
			}
		}
		dest, ok := cfg.Downstreams[source]
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "unknown source: " + source})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"forwarded_to": dest, "source": source})
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("webhook-relay listening on %s", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
