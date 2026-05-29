package authverify

import "testing"

func TestAuthVerifyParseResponse(t *testing.T) {
	// OK verdict, trailing CRLF tolerated (internal account messages carry it).
	resp, err := ParseAuthVerifyResponse([]byte(`{"request_nonce":"abc"}` + "\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Reject || resp.Nonce != "abc" {
		t.Fatalf("unexpected OK response: %+v", resp)
	}

	// Reject verdict with reason.
	resp, err = ParseAuthVerifyResponse([]byte(`{"reject":true,"reason":"nope"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Reject || resp.Reason != "nope" {
		t.Fatalf("unexpected reject response: %+v", resp)
	}

	// OK with a narrowing override.
	resp, err = ParseAuthVerifyResponse([]byte(`{"permissions":{"pub":{"allow":["foo.>"]}},"expires":123}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Permissions == nil || len(resp.Permissions.Pub.Allow) != 1 || resp.Expires != 123 {
		t.Fatalf("unexpected override response: %+v", resp)
	}

	// Empty and invalid payloads are errors (fail-closed at the caller).
	if _, err := ParseAuthVerifyResponse([]byte("\r\n")); err == nil {
		t.Fatal("expected error for empty response")
	}
	if _, err := ParseAuthVerifyResponse([]byte("{bad")); err == nil {
		t.Fatal("expected error for invalid json")
	}
}
