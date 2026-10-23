package server

import (
	"html/template"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestTOTPManualSecret(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "example", AccountName: "user@example.com"})
	require.NoError(t, err)

	manualSecret, err := totpManualSecret(key.String())
	require.NoError(t, err)
	require.Equal(t, key.Secret(), manualSecret)
	require.NotContains(t, manualSecret, "otpauth://")

	_, err = totpManualSecret("otpauth://totp/%ZZ")
	require.Error(t, err)
}

func TestTOTPTemplateSecretOnlyProvidedForEnrollment(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "example", AccountName: "user@example.com"})
	require.NoError(t, err)

	for _, test := range []struct {
		name       string
		totpKey    string
		wantSecret bool
	}{
		{name: "enrollment", totpKey: key.Secret(), wantSecret: true},
		{name: "verification", wantSecret: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			tmpl := &templates{totpVerifyTmpl: template.Must(template.New("totp").Parse("{{.TotpKey}}"))}
			request := httptest.NewRequest("GET", "/mfa/totp", nil)
			request.URL.RawQuery = url.Values{"req": []string{"request"}}.Encode()
			response := httptest.NewRecorder()

			secret := test.totpKey
			require.NoError(t, tmpl.totpVerify(request, response, "/mfa/totp", "example", "connector", "", secret, false))
			if test.wantSecret {
				require.Contains(t, response.Body.String(), key.Secret())
			} else {
				require.NotContains(t, response.Body.String(), key.Secret())
			}
			require.False(t, strings.Contains(response.Body.String(), key.String()))
		})
	}
}
