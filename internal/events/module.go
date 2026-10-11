package events

import (
	"log/slog"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/plugin/kotel"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module provides the Publisher: Kafka when brokers are configured, otherwise a logger.
var Module = fx.Module("events", fx.Provide(newPublisher))

func newPublisher(lc fx.Lifecycle, cfg config.Config, log *slog.Logger) (Publisher, error) {
	if len(cfg.KafkaBrokers) == 0 {
		return Log{Logger: log}, nil
	}
	k, err := New(cfg.KafkaBrokers, cfg.KafkaTopic, log)
	if err != nil {
		return nil, err
	}
	lc.Append(fx.StopHook(k.Close))
	return k, nil
}

// New: every produce is a span whose trace context travels in the record headers, and the
// client's broker stats are metrics (kotel).
func New(brokers []string, topic string, log *slog.Logger) (*Kafka, error) {
	tel := kotel.NewKotel(kotel.WithTracer(kotel.NewTracer()), kotel.WithMeter(kotel.NewMeter()))
	c, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.DefaultProduceTopic(topic), kgo.ProduceRequestTimeout(5*time.Second),
		kgo.WithHooks(tel.Hooks()...))
	if err != nil {
		return nil, err
	}
	return &Kafka{client: c, topic: topic, log: log}, nil
}
