// Package config loads service configuration from AUTHZ_* environment variables.
package config

import (
	"fmt"
	"strings"
	"time"
)

// Config is the process configuration.
type Config struct {
	// The public listener serves the company admin API (Connect, gRPC, gRPC-Web and REST). Only
	// APISIX may reach it: it trusts the X-Bus-* headers the gateway sets.
	PublicAddr string
	// The internal listener serves the IdP and seed Jobs. Never routed by the gateway.
	InternalAddr string
	DatabaseURL  string
	// RedisURL is the Redis master the gateway view is written to (the gateway reads a replica).
	RedisURL string
	// IdPInternalURL is the IdP UI's cluster-internal base URL (invitations).
	IdPInternalURL string
	KafkaBrokers   []string
	KafkaTopic     string
	InviteTTL      time.Duration
}

// Load reads configuration through getenv (pass os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		PublicAddr:     orDefault(getenv("AUTHZ_PUBLIC_ADDR"), ":8080"),
		InternalAddr:   orDefault(getenv("AUTHZ_INTERNAL_ADDR"), ":8081"),
		DatabaseURL:    getenv("AUTHZ_DATABASE_URL"),
		RedisURL:       getenv("AUTHZ_REDIS_URL"),
		IdPInternalURL: strings.TrimSuffix(getenv("AUTHZ_IDP_INTERNAL_URL"), "/"),
		KafkaTopic:     orDefault(getenv("AUTHZ_KAFKA_TOPIC"), "authz.events"),
		InviteTTL:      7 * 24 * time.Hour,
	}
	for _, b := range strings.Split(getenv("AUTHZ_KAFKA_BROKERS"), ",") {
		if b = strings.TrimSpace(b); b != "" {
			cfg.KafkaBrokers = append(cfg.KafkaBrokers, b)
		}
	}

	var err error
	if v := getenv("AUTHZ_INVITE_TTL"); v != "" {
		if cfg.InviteTTL, err = time.ParseDuration(v); err != nil || cfg.InviteTTL <= 0 {
			return Config{}, fmt.Errorf("AUTHZ_INVITE_TTL must be a positive duration like 168h")
		}
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("AUTHZ_DATABASE_URL is required")
	}
	if cfg.IdPInternalURL == "" {
		return Config{}, fmt.Errorf("AUTHZ_IDP_INTERNAL_URL is required")
	}
	if cfg.RedisURL == "" {
		return Config{}, fmt.Errorf("AUTHZ_REDIS_URL is required")
	}
	return cfg, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
