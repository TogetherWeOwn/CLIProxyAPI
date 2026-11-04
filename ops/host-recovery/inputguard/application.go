package inputguard

import (
	"errors"
	"io"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

var errApplication = errors.New("recovery-input-application-config-invalid")

// VerifyApplicationBundle adds host-owned application config validation to the
// existing strict subset, raw pins and exact deltas. Both config documents must
// validate. Compose and plugin-owned options still need their own schema checks;
// a successful result is neither complete preflight nor start authority.
func VerifyApplicationBundle(bundle Bundle) error {
	if err := VerifyBundle(bundle); err != nil {
		return err
	}
	for _, raw := range [][]byte{bundle.Config.Before, bundle.Config.After} {
		if config.ValidateRecoveryConfigBytes(raw) != nil {
			return errApplication
		}
	}
	return nil
}

// VerifyApplicationRequest uses the unchanged exact-input request envelope.
// The distinct pinned helper and receipt prevent a comparison-only downgrade.
func VerifyApplicationRequest(reader io.Reader) error {
	bundle, err := decodeRequest(reader)
	if err != nil {
		return err
	}
	return VerifyApplicationBundle(bundle)
}

// ServeApplication emits no input, parser error, key, filename or credential.
// It does not load plugins, resolve paths or run an application/Compose service.
func ServeApplication(reader io.Reader, writer io.Writer) bool {
	validated := VerifyApplicationRequest(reader) == nil
	line := "{\"schema\":\"host-recovery-application-input-result-v1\",\"matched\":false,\"application_validated\":false,\"start_authorized\":false}\n"
	if validated {
		line = "{\"schema\":\"host-recovery-application-input-result-v1\",\"matched\":true,\"application_validated\":true,\"start_authorized\":false}\n"
	}
	n, err := io.WriteString(writer, line)
	return validated && err == nil && n == len(line)
}
