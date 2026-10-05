// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
)

// AuthVerifyInScope reports whether a connection is subject to authentication
// verification: a JWT-based CLIENT or LEAF connection that is neither in-process
// nor bound to the system account. Internal connections (ROUTER/GATEWAY) and
// non-JWT authentication are out of scope.
func AuthVerifyInScope(kind int, inProcess, systemAccount, hasJWT bool) bool {
	if !hasJWT || inProcess || systemAccount {
		return false
	}
	return kind == CLIENT || kind == LEAF
}

// authVerificationApplies reports whether the verification callout should run for
// this already-authorized JWT connection. It is skipped when the feature is off,
// for non-JWT connections, for connections delegated to the auth callout, and for
// connections out of scope (see authVerifyInScope).
func (s *Server) authVerificationApplies(c *client, juc *jwt.UserClaims, acc *Account, opts *Options) bool {
	if !opts.AuthVerification || juc == nil || acc == nil {
		return false
	}
	// If the account delegates to the identity-substituting auth callout, that
	// path already has full control; do not also run verification.
	if acc.hasExternalAuth() {
		return false
	}
	sys := s.SystemAccount()
	isSys := sys != nil && acc == sys
	// kind and iproc are immutable after client creation.
	return AuthVerifyInScope(c.kind, c.iproc, isSys, true)
}

// authVerifyState caches a connection's verification verdict so a reload re-auth
// can re-apply the same narrowing locally instead of doing another network
// round-trip (which would block the reload and, with a slow/absent verifier, fail
// closed and disconnect an already-admitted connection). override is nil when the
// connection was admitted without any narrowing.
type authVerifyState struct {
	done     bool
	override *authverify.AuthVerifyResponse
}

// authVerifyConnection verifies an in-scope JWT connection. On the initial
// connect it performs the network round-trip (processAuthVerification) and caches
// the verdict; on a subsequent re-auth (config reload) it reuses the cached
// verdict and re-applies any narrowing locally, never contacting the verifier
// again. Returns (true, "") to admit or (false, reason) to reject.
func (s *Server) authVerifyConnection(c *client, juc *jwt.UserClaims, acc *Account, ujwt string) (bool, string) {
	c.mu.Lock()
	st := c.authVerify
	c.mu.Unlock()
	if st != nil && st.done {
		// Already verified at admission. A reload re-registered this connection
		// from its raw JWT, dropping the narrowing; re-apply the cached override
		// locally so the verdict persists without another round-trip.
		if st.override != nil {
			if err := s.applyAuthVerifyOverride(c, juc, acc, st.override); err != nil {
				return false, fmt.Sprintf("could not re-apply auth verification override: %v", err)
			}
		}
		return true, _EMPTY_
	}
	return s.processAuthVerification(c, juc, acc, ujwt)
}

// cacheAuthVerify records the admit verdict for c so a later reload re-auth can
// re-apply it locally. Only the narrowing-relevant fields are kept; an admit with
// no override caches a nil override, leaving the (already correct) raw-JWT
// permissions in place on re-auth.
func (c *client) cacheAuthVerify(resp *authverify.AuthVerifyResponse) {
	var override *authverify.AuthVerifyResponse
	if resp != nil && (resp.Permissions != nil || resp.Expires != 0) {
		override = &authverify.AuthVerifyResponse{Permissions: resp.Permissions, Expires: resp.Expires}
	}
	c.mu.Lock()
	c.authVerify = &authVerifyState{done: true, override: override}
	c.mu.Unlock()
}

// processAuthVerification publishes a verification request for c in the system
// account and waits for a verdict. It returns (true, "") to admit, or
// (false, reason) to reject. It fails closed: a missing system account, transport
// error, timeout, bad/forged-nonce response, or override-apply error all reject.
func (s *Server) processAuthVerification(c *client, juc *jwt.UserClaims, acc *Account, ujwt string) (bool, string) {
	sys := s.SystemAccount()
	if sys == nil {
		return false, "auth verification requires a system account"
	}

	var nb [nonceLen]byte
	s.generateNonce(nb[:])
	nonce := string(nb[:])

	reply := s.newRespInbox()
	respCh := make(chan string, 1)
	// Non-blocking send: only the first response is consumed, so additional
	// responses (e.g. several non-queue verification services replying to the same
	// inbox) are dropped instead of blocking the internal delivery goroutine on a
	// full channel.
	send := func(reason string) {
		select {
		case respCh <- reason:
		default:
		}
	}

	processReply := func(_ *subscription, rc *client, _ *Account, _, _ string, rmsg []byte) {
		_, msg := rc.msgParts(rmsg)
		resp, err := authverify.ParseAuthVerifyResponse(msg)
		if err != nil {
			send(fmt.Sprintf("invalid auth verification response: %v", err))
			return
		}
		if resp.Nonce != nonce {
			send("auth verification response nonce mismatch")
			return
		}
		if resp.Reject {
			reason := resp.Reason
			if reason == _EMPTY_ {
				reason = "rejected by auth verification service"
			}
			send(reason)
			return
		}
		if err := s.applyAuthVerifyOverride(c, juc, acc, resp); err != nil {
			send(fmt.Sprintf("could not apply auth verification override: %v", err))
			return
		}
		// Cache the admit verdict so a later reload re-auth can re-apply the same
		// narrowing locally without another round-trip.
		c.cacheAuthVerify(resp)
		send(_EMPTY_)
	}

	sub, err := sys.subscribeInternal(reply, processReply)
	if err != nil {
		return false, fmt.Sprintf("error setting up auth verification reply subscription: %v", err)
	}
	defer sys.unsubscribeInternal(sub)

	req, err := json.Marshal(s.buildAuthVerifyRequest(c, juc, acc, nonce, ujwt))
	if err != nil {
		return false, fmt.Sprintf("error encoding auth verification request: %v", err)
	}
	if err := s.sendInternalAccountMsgWithReply(sys, authverify.AuthVerificationSubject, reply, nil, req, false); err != nil {
		return false, fmt.Sprintf("error sending auth verification request: %v", err)
	}

	timer := time.NewTimer(authverify.AuthVerificationTimeout)
	defer timer.Stop()
	select {
	case reason := <-respCh:
		return reason == _EMPTY_, reason
	case <-timer.C:
		return false, "auth verification response not received in time"
	}
}

// buildAuthVerifyRequest assembles the request payload from the client, the
// verified user claims, and the bound account.
func (s *Server) buildAuthVerifyRequest(c *client, juc *jwt.UserClaims, acc *Account, nonce, ujwt string) *authverify.AuthVerifyRequest {
	req := &authverify.AuthVerifyRequest{
		Nonce:    nonce,
		UserNkey: juc.Subject,
		Account:  acc.Name,
	}
	s.mu.RLock()
	req.Server = jwt.ServerID{
		Name:    s.info.Name,
		Host:    s.info.Host,
		ID:      s.info.ID,
		Version: s.info.Version,
		Cluster: s.info.Cluster,
	}
	s.mu.RUnlock()

	c.mu.Lock()
	c.fillClientInfo(&req.Client)
	c.fillConnectOpts(&req.Connect, ujwt)
	if req.Connect.SignedNonce != _EMPTY_ {
		req.Client.Nonce = string(c.nonce)
	}
	if c.flags.isSet(handshakeComplete) && c.nc != nil {
		req.TLS = clientTLSInfo(c.nc)
	}
	c.mu.Unlock()
	return req
}

// clientTLSInfo extracts TLS state for the request, mirroring the auth callout.
func clientTLSInfo(nc net.Conn) *jwt.ClientTLS {
	conn, ok := nc.(*tls.Conn)
	if !ok {
		return nil
	}
	cs := conn.ConnectionState()
	ct := &jwt.ClientTLS{
		Version: tlsVersion(cs.Version),
		Cipher:  tls.CipherSuiteName(cs.CipherSuite),
	}
	for _, vs := range cs.VerifiedChains {
		var certs []string
		for _, cert := range vs {
			certs = append(certs, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		}
		ct.VerifiedChains = append(ct.VerifiedChains, certs)
	}
	if len(ct.VerifiedChains) == 0 {
		for _, cert := range cs.PeerCertificates {
			ct.Certs = append(ct.Certs, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		}
	}
	return ct
}

// applyAuthVerifyOverride narrows the verified user's claims by the override and
// re-registers the user on the connection. Narrowing is delegated to package
// authverify and can never escalate.
func (s *Server) applyAuthVerifyOverride(c *client, juc *jwt.UserClaims, acc *Account, resp *authverify.AuthVerifyResponse) error {
	changed := false
	if resp.Permissions != nil {
		narrowed := authverify.NarrowPermissions(effectiveJWTPermissions(juc, acc), resp.Permissions)
		juc.Permissions = *narrowed
		changed = true
	}
	if resp.Expires != 0 {
		juc.Expires = authverify.NarrowExpiry(juc.Expires, resp.Expires)
		changed = true
	}
	if !changed {
		return nil
	}
	allowedConnTypes, err := convertAllowedConnectionTypes(juc.AllowedConnectionTypes)
	if err != nil && len(allowedConnTypes) == 0 {
		return err
	}
	nkey := buildInternalNkeyUser(juc, allowedConnTypes, acc)
	if err := c.RegisterNkeyUser(nkey); err != nil {
		return err
	}
	_, validFor := validateTimes(juc)
	c.setExpiration(juc.Claims(), validFor)
	return nil
}

// effectiveJWTPermissions returns the permissions in effect for juc, as
// buildInternalNkeyUser applies them: the user JWT permissions, or the account
// default permissions when the user JWT has none. Narrowing must start from
// these, or an override would drop the account defaults.
func effectiveJWTPermissions(juc *jwt.UserClaims, acc *Account) *jwt.Permissions {
	if buildPermissionsFromJwt(&juc.Permissions) != nil {
		return &juc.Permissions
	}
	acc.mu.RLock()
	dp := acc.defaultPerms.clone()
	acc.mu.RUnlock()
	out := &jwt.Permissions{}
	if dp == nil {
		return out
	}
	if dp.Publish != nil {
		out.Pub = jwt.Permission{Allow: dp.Publish.Allow, Deny: dp.Publish.Deny}
	}
	if dp.Subscribe != nil {
		out.Sub = jwt.Permission{Allow: dp.Subscribe.Allow, Deny: dp.Subscribe.Deny}
	}
	if dp.Response != nil {
		out.Resp = &jwt.ResponsePermission{MaxMsgs: dp.Response.MaxMsgs, Expires: dp.Response.Expires}
	}
	return out
}
