// Package config loads service configuration from AUTHZ_* environment variables.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Config is the process configuration.
type Config struct {
	// Public listeners serve the company admin API (REST and gRPC). Only APISIX may reach them:
	// they trust the X-Bus-* headers / x-bus-* metadata it sets.
	PublicAddr     string
	PublicGRPCAddr string
	// Internal listeners serve the IdP, seed Jobs and OPA bundles. Never routed by the gateway.
	InternalAddr     string
	InternalGRPCAddr string
	DatabaseURL      string
	// IdPInternalURL is the IdP UI's cluster-internal base URL (invitations).
	IdPInternalURL string
	KafkaBrokers   []string
	KafkaTopic     string
	// BundleService is the name OPA's boot config gives this service; discovery refers to it.
	BundleService string
	// LongPollSeconds is what discovery tells OPA to use for every bundle.
	LongPollSeconds int
	InviteTTL       time.Duration
}

// Load reads configuration through getenv (pass os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		PublicAddr:       orDefault(getenv("AUTHZ_PUBLIC_ADDR"), ":8080"),
		PublicGRPCAddr:   orDefault(getenv("AUTHZ_PUBLIC_GRPC_ADDR"), ":9090"),
		InternalAddr:     orDefault(getenv("AUTHZ_INTERNAL_ADDR"), ":8081"),
		InternalGRPCAddr: orDefault(getenv("AUTHZ_INTERNAL_GRPC_ADDR"), ":9091"),
		DatabaseURL:      getenv("AUTHZ_DATABASE_URL"),
		IdPInternalURL:   strings.TrimSuffix(getenv("AUTHZ_IDP_INTERNAL_URL"), "/"),
		KafkaTopic:       orDefault(getenv("AUTHZ_KAFKA_TOPIC"), "authz.events"),
		BundleService:    orDefault(getenv("AUTHZ_BUNDLE_SERVICE"), "authz"),
		InviteTTL:        7 * 24 * time.Hour,
	}
	for _, b := range strings.Split(getenv("AUTHZ_KAFKA_BROKERS"), ",") {
		if b = strings.TrimSpace(b); b != "" {
			cfg.KafkaBrokers = append(cfg.KafkaBrokers, b)
		}
	}

	var err error
	if cfg.LongPollSeconds, err = strconv.Atoi(orDefault(getenv("AUTHZ_LONG_POLL_SECONDS"), "30")); err != nil || cfg.LongPollSeconds < 1 {
		return Config{}, fmt.Errorf("AUTHZ_LONG_POLL_SECONDS must be a positive integer")
	}
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
	return cfg, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
