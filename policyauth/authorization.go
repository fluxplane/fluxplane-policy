// Package policyauth defines runtime authorization context helpers that host
// runtimes can attach to context.Context while keeping the root policy package
// pure.
package policyauth

import (
	"context"

	policy "github.com/fluxplane/fluxplane-policy"
)

// AuthorizationContext is the turn-local policy evaluation context carried by a
// host runtime while projecting or executing capabilities.
type AuthorizationContext struct {
	Policy      policy.AuthorizationPolicy `json:"policy,omitempty"`
	Subjects    []policy.SubjectRef        `json:"subjects,omitempty"`
	Trust       policy.Trust               `json:"trust,omitempty"`
	TraceAllows bool                       `json:"trace_allows,omitempty"`
}

type authorizationContextKey struct{}

// ContextWithAuthorization stores authorization context on ctx. A nil ctx is
// replaced with context.Background for compatibility with the original core
// helper behavior.
func ContextWithAuthorization(ctx context.Context, auth AuthorizationContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, authorizationContextKey{}, auth)
}

// AuthorizationFromContext returns authorization context from ctx.
func AuthorizationFromContext(ctx context.Context) (AuthorizationContext, bool) {
	if ctx == nil {
		return AuthorizationContext{}, false
	}
	auth, ok := ctx.Value(authorizationContextKey{}).(AuthorizationContext)
	return auth, ok
}
