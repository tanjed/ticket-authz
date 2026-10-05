package rpcapi

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/bundle"
)

// Bundle implements BundleService: the signed bundles, for operators and tools.
type Bundle struct {
	authzv1connect.UnimplementedBundleServiceHandler
	Svc BundleBackend
	Log *slog.Logger
}

func (s *Bundle) ListBundles(ctx context.Context, _ *authzv1.ListBundlesRequest) (*authzv1.ListBundlesResponse, error) {
	list, err := s.Svc.List(ctx)
	if err != nil {
		return nil, toError(s.Log, err)
	}
	out := &authzv1.ListBundlesResponse{}
	for _, b := range list {
		out.Bundles = append(out.Bundles, bundleInfoPB(b))
	}
	return out, nil
}

func (s *Bundle) GetBundle(ctx context.Context, req *authzv1.GetBundleRequest) (*authzv1.GetBundleResponse, error) {
	b, ok, err := s.Svc.Get(ctx, req.GetName())
	if err != nil {
		return nil, toError(s.Log, err)
	}
	if !ok {
		return nil, withReason(connect.CodeNotFound, "bundle_not_found", "no such bundle")
	}
	return &authzv1.GetBundleResponse{Bundle: bundleInfoPB(b.Info), Body: b.Body}, nil
}

func bundleInfoPB(b bundle.Info) *authzv1.BundleInfo {
	return &authzv1.BundleInfo{Name: b.Name, Revision: b.Revision}
}
