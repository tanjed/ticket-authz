package admin

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/service/role"
)

func rolePB(r role.Role) *authzv1.Role {
	return &authzv1.Role{
		Id: r.ID, Name: r.Name, Protected: r.Protected, GrantsAll: r.GrantsAll, Version: int32(r.Version),
		Permissions: r.Permissions, CreateTime: timestamppb.New(r.CreatedAt), UpdateTime: timestamppb.New(r.UpdatedAt), LandingPath: r.LandingPath,
	}
}
