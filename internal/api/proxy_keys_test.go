package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"turnsapi/internal/proxykey"

	"github.com/gin-gonic/gin"
)

func findProxyKeyByID(t *testing.T, manager *proxykey.Manager, id string) *proxykey.ProxyKey {
	t.Helper()

	key, ok := manager.GetKey(id)
	if !ok {
		t.Fatalf("proxy key %s not found", id)
	}
	return key
}

func TestHandleUpdateProxyKey_PreservesEnforceModelMappingsWhenFieldOmitted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	manager := proxykey.NewManager()
	key, err := manager.GenerateKeyWithPolicy("share", "test", []string{}, nil, true)
	if err != nil {
		t.Fatalf("GenerateKeyWithPolicy() error = %v", err)
	}

	server := &MultiProviderServer{
		proxyKeyManager: manager,
	}

	body := []byte(`{"name":"share","description":"updated","is_active":true,"allowedGroups":[]}`)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: key.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPut, "/admin/proxy-keys/"+key.ID, bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	server.handleUpdateProxyKey(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("handleUpdateProxyKey() status = %d, want %d, body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	updatedKey := findProxyKeyByID(t, manager, key.ID)
	if !updatedKey.EnforceModelMappings {
		t.Fatalf("EnforceModelMappings = false, want true when field is omitted")
	}
}

func TestHandleUpdateProxyKey_AcceptsSnakeCasePolicyField(t *testing.T) {
	gin.SetMode(gin.TestMode)

	manager := proxykey.NewManager()
	key, err := manager.GenerateKeyWithPolicy("share", "test", []string{}, nil, false)
	if err != nil {
		t.Fatalf("GenerateKeyWithPolicy() error = %v", err)
	}

	server := &MultiProviderServer{
		proxyKeyManager: manager,
	}

	body := []byte(`{"name":"share","description":"updated","is_active":true,"allowed_groups":[],"enforce_model_mappings":true}`)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Params = gin.Params{{Key: "id", Value: key.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPut, "/admin/proxy-keys/"+key.ID, bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	server.handleUpdateProxyKey(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("handleUpdateProxyKey() status = %d, want %d, body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	updatedKey := findProxyKeyByID(t, manager, key.ID)
	if !updatedKey.EnforceModelMappings {
		t.Fatalf("EnforceModelMappings = false, want true when snake_case field is used")
	}
}
