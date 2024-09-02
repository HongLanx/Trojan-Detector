package check

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpClient_GetJson(t *testing.T) {

	t.Run("given valid json response then no error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
			rw.Write(loadResponse(t, "json_response.json"))
		}))
		defer server.Close()

		client := newHttpClient(server.Client())
		var response map[string]string
		err := client.GetJson(server.URL, nil, nil, &response)

		require.NoError(t, err)
		assert.Equal(t, "ok", response["secure"])
	})

	t.Run("given invalid json response then error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
			rw.Write([]byte("--- invalid json ---"))
		}))
		defer server.Close()

		client := newHttpClient(server.Client())
		var response map[string]string
		err := client.GetJson(server.URL, nil, nil, &response)

		require.Error(t, err)
	})

	t.Run("given non 2xx response then error is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write(nil)
		}))
		defer server.Close()

		client := newHttpClient(server.Client())
		var response map[string]string
		err := client.GetJson(server.URL, nil, nil, &response)

		require.Error(t, err)
	})
}
