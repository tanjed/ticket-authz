package admin

import (
	"context"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/router"
)

func (a *Admin) ListPermissions(ctx context.Context, _ *authzv1.ListPermissionsRequest) (*authzv1.ListPermissionsResponse, error) {
	if _, err := callerFrom(ctx); err != nil {
		return nil, err
	}
	list, err := a.Permissions.Permissions(ctx)
	if err != nil {
		return nil, router.Error(a.Log, err)
	}
	out := &authzv1.ListPermissionsResponse{}
	for _, p := range list {
		out.Permissions = append(out.Permissions, &authzv1.Permission{Key: p.Key, Service: p.Service, Description: p.Description})
	}
	return out, nil
}
