// Package resync republishes the whole authorization state to Redis at boot: it fills a fresh or
// flushed Redis, repairs a publish that failed, and deletes keys of what no longer exists.
package resync

import (
	"context"
	"fmt"
	"time"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// timeout bounds the whole resync (it reads every role and member).
const timeout = time.Minute

type Service struct {
	uow       uow.Transactor
	cache     cache.Publisher
	catalogue catalogrepo.Repo
	roles     rolerepo.Repo
	company   company.Client
	users     userrepo.Repo
}

// Resync reads the whole state from the primary (in a unit of work) and replaces Redis with it.
// Company statuses come from Company (pending_setup is not published); Company unreachable fails
// the resync, and with it the boot. No lock: a write committing meanwhile may be overwritten until it next changes (accepted).
func (s *Service) Resync(ctx context.Context) error {
	var st cache.State
	statuses, err := s.company.ListCompanyStatuses(ctx)
	if err != nil {
		return fmt.Errorf("company statuses: %w", err)
	}
	st.Companies = map[string]string{}
	for id, status := range statuses {
		if status == company.StatusActive || status == company.StatusSuspended {
			st.Companies[id] = status
		}
	}
	err = s.uow.UnitOfWork(ctx, timeout, func(ctx context.Context) error {
		var err error
		if st.Routes, err = s.catalogue.RoutesView(ctx); err != nil {
			return err
		}
		if st.Consumer, err = s.catalogue.ConsumerView(ctx); err != nil {
			return err
		}
		if st.Roles, err = s.roles.View(ctx); err != nil {
			return err
		}
		st.Users, err = s.users.Versions(ctx)
		return err
	})
	if err != nil {
		return err
	}
	if err := s.cache.Replace(ctx, st); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return nil
}
