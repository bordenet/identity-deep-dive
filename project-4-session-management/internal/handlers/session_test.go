package handlers

import (
	"testing"

	"github.com/bordenet/identity-deep-dive/project-4-session-management/pkg/models"
)

func TestCreateSessionRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     models.CreateSessionRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: models.CreateSessionRequest{
				TenantID: "tenant-1",
				UserID:   "user-1",
				Scope:    "read write",
			},
			wantErr: false,
		},
		{
			name: "missing tenant_id",
			req: models.CreateSessionRequest{
				UserID: "user-1",
				Scope:  "read write",
			},
			wantErr: true,
		},
		{
			name: "missing user_id",
			req: models.CreateSessionRequest{
				TenantID: "tenant-1",
				Scope:    "read write",
			},
			wantErr: true,
		},
		{
			name: "missing scope",
			req: models.CreateSessionRequest{
				TenantID: "tenant-1",
				UserID:   "user-1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSessionRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		req     models.ValidateSessionRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: models.ValidateSessionRequest{
				AccessToken: "valid.jwt.token",
			},
			wantErr: false,
		},
		{
			name:    "missing access_token",
			req:     models.ValidateSessionRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
