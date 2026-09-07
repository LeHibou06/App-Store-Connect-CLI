package web

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	webcore "github.com/rudrankriyam/App-Store-Connect-CLI/internal/web"
)

type ephemeralSessionContextKey struct{}

// ContextWithEphemeralSession gates the exact read-only command surface before
// credential access. The marker selects a resolver that cannot persist or log in.
func ContextWithEphemeralSession(ctx context.Context, command string, fs *flag.FlagSet) (context.Context, error) {
	switch command {
	case "asc web removed-apps list", "asc web api-keys list", "asc web api-keys view":
	default:
		return nil, shared.UsageError(command + " does not support --experimental-web-session")
	}
	var unsupported string
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "provider-id", "public-provider-id", "two-factor-code-command":
			if unsupported == "" {
				unsupported = f.Name
			}
		}
	})
	if unsupported != "" {
		return nil, shared.UsageError("--" + unsupported + " is unsupported with --experimental-web-session")
	}
	return context.WithValue(ctx, ephemeralSessionContextKey{}, true), nil
}

func resolveEphemeralWebSession(ctx context.Context, appleID string) (*webcore.AuthSession, error) {
	for _, name := range []string{"ASC_WEB_SESSION_PROVIDER", "ASC_WEB_SESSION_CSRF"} {
		if os.Getenv(name) != "" {
			return nil, shared.UsageError(name + " is unsupported with --experimental-web-session")
		}
	}
	value := os.Getenv(webSessionBundleEnvName)
	if strings.TrimSpace(value) == "" {
		return nil, shared.UsageError(webSessionBundleEnvName + " is unset or empty when --experimental-web-session is used")
	}
	if len(value) > webcore.MaxSessionBundleSize {
		return nil, shared.UsageError(fmt.Sprintf("%s exceeds %d-byte limit", webSessionBundleEnvName, webcore.MaxSessionBundleSize))
	}
	bundle, err := webcore.DecodeSessionBundle([]byte(value))
	if err != nil {
		// Decoder errors may contain caller-controlled credential fields.
		return nil, shared.UsageError("invalid session bundle from " + webSessionBundleEnvName)
	}
	if appleID = strings.TrimSpace(appleID); appleID != "" && !strings.EqualFold(appleID, strings.TrimSpace(bundle.AppleID)) {
		return nil, shared.UsageError("session bundle does not match --apple-id")
	}
	shared.ApplyRootLoggingOverrides()
	validationCtx, cancel := newWebRequestContext(ctx)
	defer cancel()
	session, err := webcore.OpenValidatedSessionBundle(validationCtx, bundle)
	if err != nil {
		return nil, fmt.Errorf("ephemeral web session validation failed; supply a fresh canonical ASC_WEB_SESSION bundle")
	}
	return session, nil
}
