package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/bordenet/identity-deep-dive/project-2-session-management/internal/tokens"
	"github.com/gorilla/mux"
)

// JWKSHandler handles JWKS endpoint for public key distribution
type JWKSHandler struct {
	keyManager *tokens.TenantKeyManager
}

// NewJWKSHandler creates a new JWKS handler
func NewJWKSHandler(keyManager *tokens.TenantKeyManager) *JWKSHandler {
	return &JWKSHandler{
		keyManager: keyManager,
	}
}

// GetJWKS handles GET /tenants/{tenant_id}/jwks
func (h *JWKSHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]

	if tenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}

	// Get JWKS document for tenant
	jwks, err := h.keyManager.GetJWKS(tenantID)
	if err != nil {
		http.Error(w, "Failed to get JWKS: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return JWKS document
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(jwks)
}
