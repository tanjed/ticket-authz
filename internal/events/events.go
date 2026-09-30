// Package events publishes Authz's domain events to one Kafka topic (authz.events), with the
// IdP's envelope: { id, event, occurred_at, source, data }, keyed by company id.
package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/twmb/franz-go/pkg/kgo"
)

const (
	CompanyRegistered  = "COMPANY_REGISTERED"
	RoleCreated        = "ROLE_CREATED"
	RoleUpdated        = "ROLE_UPDATED"
	RoleDeleted        = "ROLE_DELETED"
	MemberAdded        = "MEMBER_ADDED"
	MemberRolesChanged = "MEMBER_ROLES_CHANGED"
	MemberRemoved      = "MEMBER_REMOVED"
	MemberInvited      = "MEMBER_INVITED"
)

// Publisher is called after the database commit. Publishing is best effort: a failure is
// logged and never fails the request (there is no outbox yet).
type Publisher interface {
	Publish(ctx context.Context, event, companyID string, data map[string]any)
}

var (
	_ Publisher = (*Kafka)(nil)
	_ Publisher = Log{}
)

type envelope struct {
	ID         string         `json:"id"`
	Event      string         `json:"event"`
	OccurredAt time.Time      `json:"occurred_at"`
	Source     string         `json:"source"`
	Data       map[string]any `json:"data"`
}

func encode(event string, data map[string]any) []byte {
	b, _ := json.Marshal(envelope{ID: uuid.NewString(), Event: event, OccurredAt: time.Now().UTC(), Source: "authz", Data: data})
	return b
}

// Kafka publishes with acks=all and an idempotent producer.
type Kafka struct {
	client *kgo.Client
	topic  string
	log    *slog.Logger
}

func NewKafka(brokers []string, topic string, log *slog.Logger) (*Kafka, error) {
	c, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.DefaultProduceTopic(topic), kgo.ProduceRequestTimeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	return &Kafka{client: c, topic: topic, log: log}, nil
}

func (k *Kafka) Publish(ctx context.Context, event, companyID string, data map[string]any) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	rec := &kgo.Record{Key: []byte(companyID), Value: encode(event, data), Headers: []kgo.RecordHeader{{Key: "event", Value: []byte(event)}}}
	if err := k.client.ProduceSync(ctx, rec).FirstErr(); err != nil {
		k.log.Error("event not published", "event", event, "company_id", companyID, "err", err)
	}
}

func (k *Kafka) Close() { k.client.Close() }

// Log is the publisher when no brokers are configured: events are only logged.
type Log struct{ Logger *slog.Logger }

func (l Log) Publish(_ context.Context, event, companyID string, data map[string]any) {
	l.Logger.Info("event (no Kafka configured)", "event", event, "company_id", companyID, "data", data)
}
