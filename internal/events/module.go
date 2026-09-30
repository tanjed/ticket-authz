package events

import (
	"log/slog"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module provides the Publisher: Kafka when brokers are configured, otherwise a logger.
var Module = fx.Module("events", fx.Provide(newPublisher))

func newPublisher(lc fx.Lifecycle, cfg config.Config, log *slog.Logger) (Publisher, error) {
	if len(cfg.KafkaBrokers) == 0 {
		return Log{Logger: log}, nil
	}
	k, err := NewKafka(cfg.KafkaBrokers, cfg.KafkaTopic, log)
	if err != nil {
		return nil, err
	}
	lc.Append(fx.StopHook(k.Close))
	return k, nil
}
