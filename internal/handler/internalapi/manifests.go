package internalapi

import (
	"context"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/router"
)

func (s *Internal) ApplyManifest(ctx context.Context, req *authzv1.ApplyManifestRequest) (*authzv1.ApplyManifestResponse, error) {
	m := catalogue.Manifest{}
	for _, p := range req.GetPermissions() {
		m.Permissions = append(m.Permissions, catalogue.Permission{Key: p.GetKey(), Description: p.GetDescription(), Consumer: p.GetConsumer()})
	}
	for _, r := range req.GetRoutes() {
		m.Routes = append(m.Routes, catalogue.Route{Name: r.GetName(), Permission: r.GetPermission(), Public: r.GetPublic()})
	}
	res, err := s.Catalogue.ApplyManifest(ctx, req.GetService(), m)
	if err != nil {
		return nil, router.Error(s.Log, err)
	}
	return &authzv1.ApplyManifestResponse{
		Service: res.Service, Permissions: int32(res.Permissions), Routes: int32(res.Routes), Changed: res.Changed,
	}, nil
}
