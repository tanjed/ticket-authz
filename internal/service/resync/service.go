// Package resync republishes the whole authorization state to Redis at boot: it fills a fresh or
// flushed Redis, repairs a publish that failed, and deletes keys of what no longer exists.
package resync

import (
	"context"
	"fmt"
	"time"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	companyrepo "github.com/tanjed/bus2/authz/internal/repository/company"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// timeout bounds the whole resync (it reads every role and member).
const timeout = time.Minute

type Service struct {
	uow       uow.Transactor
	cache     cache.Publisher
	catalogue catalogrepo.Repo
	roles     rolerepo.Repo
	companies companyrepo.Repo
	members   memberrepo.Repo
}

// Resync reads the whole state from the primary (in a unit of work) and replaces Redis with it.
// No lock: a write committing meanwhile may be overwritten until it next changes (accepted).
func (s *Service) Resync(ctx context.Context) error {
	var st cache.State
	err := s.uow.UnitOfWork(ctx, timeout, func(ctx context.Context) error {
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
		if st.Companies, err = s.companies.Statuses(ctx); err != nil {
			return err
		}
		st.Users, err = s.members.Versions(ctx)
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
