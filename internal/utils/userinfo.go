package utils

import "github.com/luikymagno/auth-server/internal/models"

func HandleUserInfoRequest(ctx Context, authzHeader string) (models.UserInfoResponse, error) {
	return models.UserInfoResponse{}, nil
}
