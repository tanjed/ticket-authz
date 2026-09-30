// Package idp calls the IdP UI's internal API (identity lookup, invitation delivery). The IdP
// refuses these calls on its public host, so BaseURL must be the cluster-internal one.
package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Client is what rbac needs from the IdP.
type Client interface {
	// IdentityByPhone returns the identity id for a phone, or "" if there is none.
	IdentityByPhone(ctx context.Context, phone string) (string, error)
	SendInvitation(ctx context.Context, inv Invitation) error
}

type Invitation struct {
	ID          string    `json:"invitation_id"`
	Phone       string    `json:"phone"`
	CompanyName string    `json:"company_name"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type HTTP struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *HTTP {
	return &HTTP{BaseURL: baseURL, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func (c *HTTP) IdentityByPhone(ctx context.Context, phone string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/internal/identities?phone="+url.QueryEscape(phone), nil)
	if err != nil {
		return "", err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("idp identity lookup: %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotFound:
		return "", nil
	case http.StatusOK:
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil || body.ID == "" {
			return "", fmt.Errorf("idp identity lookup: bad response")
		}
		return body.ID, nil
	default:
		return "", fmt.Errorf("idp identity lookup: status %d", res.StatusCode)
	}
}

func (c *HTTP) SendInvitation(ctx context.Context, inv Invitation) error {
	b, _ := json.Marshal(inv)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/internal/invitations", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("idp send invitation: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("idp send invitation: status %d", res.StatusCode)
	}
	return nil
}
