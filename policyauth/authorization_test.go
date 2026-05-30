package policyauth

import (
	"context"
	"reflect"
	"testing"

	policy "github.com/fluxplane/fluxplane-policy"
)

func TestAuthorizationContextRoundTrip(t *testing.T) {
	if _, ok := AuthorizationFromContext(nil); ok { //nolint:staticcheck // nil context handling is the behavior under test.
		t.Fatal("AuthorizationFromContext(nil) ok = true")
	}

	auth := AuthorizationContext{
		Policy:      policy.AuthorizationPolicy{Grants: []policy.Grant{{Subjects: []policy.SubjectRef{{Kind: policy.SubjectUser, ID: "u"}}}}},
		Subjects:    []policy.SubjectRef{{Kind: policy.SubjectUser, ID: "u"}},
		Trust:       policy.Trust{Kind: policy.TrustInvocation, Level: policy.TrustPrivileged},
		TraceAllows: true,
	}
	ctx := ContextWithAuthorization(nil, auth) //nolint:staticcheck // nil context handling is the behavior under test.
	got, ok := AuthorizationFromContext(ctx)
	if !ok || !reflect.DeepEqual(got, auth) {
		t.Fatalf("AuthorizationFromContext() = %#v, %v; want %#v, true", got, ok, auth)
	}

	if _, ok := AuthorizationFromContext(context.Background()); ok {
		t.Fatal("AuthorizationFromContext(background) ok = true")
	}
}
