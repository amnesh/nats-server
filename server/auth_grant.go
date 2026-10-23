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
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server/authverify"
)

var (
	ErrUnknownClient          = errors.New("unknown client")
	ErrStaleGeneration        = errors.New("stale grant generation")
	ErrNotGrantMode           = errors.New("connection is not in grant mode")
	ErrGrantRejected          = errors.New("grant rejected")
	errAuthGrantResourceLimit = errors.New("auth grant resource limit")
)

type authGrantState struct {
	hook                                authverify.GrantHook
	serverID                            string
	account, user                       string
	grant                               authverify.Grant
	generation                          uint64
	expires, jwtExpires                 int64
	deadline                            time.Time
	timerVersion                        uint64
	done, closeComplete, closedNotified bool
}

func (s *Server) authGrantApplies(c *client, juc *jwt.UserClaims, acc *Account, raw string) (bool, error) {
	_, static, err := decodeAuthModeJWT(raw, true)
	if err != nil {
		return false, err
	}
	if static && juc.Issuer != acc.Name {
		return false, errors.New("user authverify block requires the account identity signer")
	}
	acc.mu.RLock()
	mode := acc.authMode
	acc.mu.RUnlock()
	applies := mode == authModeGrant && !static && (c.kind == CLIENT || c.kind == LEAF) && acc != s.SystemAccount()
	c.mu.Lock()
	st := c.authGrant
	changed := st != nil && (!applies || st.account != acc.Name || st.user != juc.Subject)
	c.mu.Unlock()
	if changed {
		return false, errors.New("cannot change a grant connection identity")
	}
	if applies {
		scope, _, ok := acc.issuerScopeAndXPermissions(juc.Issuer)
		if _, scoped := scope.(*jwt.UserScope); !ok || !scoped {
			return false, errors.New("grant mode requires a scoped signing key")
		}
	}
	return applies, nil
}

func invokeGrantHook(h authverify.GrantHook, req *authverify.GrantRequest) (v *authverify.GrantVerdict) {
	defer func() {
		if recover() != nil {
			v = nil
		}
	}()
	return h.Verify(req)
}

func (s *Server) authGrantConnection(c *client, juc *jwt.UserClaims, acc *Account, raw string, hook authverify.GrantHook) bool {
	c.mu.Lock()
	if st := c.authGrant; st != nil {
		if c.isClosed() {
			c.mu.Unlock()
			return false
		}
		perms, pub, sub, err := compileAuthGrant(st.grant)
		if err != nil {
			c.mu.Unlock()
			return false
		}
		allowNow, validFor := validateTimes(juc)
		if !allowNow {
			c.mu.Unlock()
			return false
		}
		c.installAuthGrant(perms, pub, sub)
		st.jwtExpires = juc.Expires
		st.deadline = time.Time{}
		if validFor != 0 {
			st.deadline = time.Now().Add(validFor)
		}
		c.setGrantExpiration(st)
		c.mu.Unlock()
		return true
	}
	c.mu.Unlock()
	if hook == nil {
		return false
	}
	scope, _, _ := acc.issuerScopeAndXPermissions(juc.Issuer)
	us, ok := scope.(*jwt.UserScope)
	if !ok {
		return false
	}
	base := s.buildAuthVerifyRequest(c, juc, acc, "", raw)
	req := &authverify.GrantRequest{Server: base.Server, UserNkey: base.UserNkey, Account: base.Account,
		Client: base.Client, Connect: base.Connect, TLS: base.TLS, Issuer: juc.Issuer, ScopeRole: us.Role}
	v := invokeGrantHook(hook, req)
	if v == nil {
		return false
	}
	if v.Reject {
		if v.Reason != "" {
			c.Debugf("Auth grant rejected connection: %s", v.Reason)
		}
		if v.Code == authverify.CodeResourceLimit {
			c.setAuthError(errAuthGrantResourceLimit)
		}
		return false
	}
	applied := false
	defer func() {
		if !applied && v.Done != nil {
			v.Done(false)
		}
	}()
	if v.Generation == 0 || v.Done == nil {
		return false
	}
	grant := cloneAuthGrant(v.Grant)
	perms, pub, sub, err := compileAuthGrant(grant)
	if err != nil {
		c.Debugf("Invalid auth grant: %v", err)
		return false
	}
	allowNow, validFor := validateTimes(juc)
	if !allowNow {
		return false
	}
	st := &authGrantState{hook: hook, serverID: req.Server.ID, account: acc.Name, user: juc.Subject,
		grant: grant, generation: v.Generation, expires: v.Expires, jwtExpires: juc.Expires}
	if validFor != 0 {
		st.deadline = time.Now().Add(validFor)
	}
	c.mu.Lock()
	if c.isClosed() || c.user == nil || c.acc != acc {
		c.mu.Unlock()
		return false
	}
	c.authGrant = st
	c.installAuthGrant(perms, pub, sub)
	c.setGrantExpiration(st)
	applied = true
	c.mu.Unlock()
	v.Done(true)
	c.mu.Lock()
	st.done = true
	c.notifyGrantClosed(st)
	c.mu.Unlock()
	return true
}

func cloneAuthGrant(g authverify.Grant) authverify.Grant {
	clone := func(p authverify.SubjectGrant) authverify.SubjectGrant {
		return authverify.SubjectGrant{Allow: slices.Clone(p.Allow), AllowPrefix: slices.Clone(p.AllowPrefix), Deny: slices.Clone(p.Deny)}
	}
	g.Pub, g.Sub = clone(g.Pub), clone(g.Sub)
	if g.Resp != nil {
		r := *g.Resp
		g.Resp = &r
	}
	return g
}

func compileAuthGrant(g authverify.Grant) (*Permissions, grantPrefixRules, grantPrefixRules, error) {
	for _, list := range [][]string{g.Pub.Allow, g.Pub.Deny, g.Sub.Allow, g.Sub.Deny} {
		if len(list) > maxPermTemplateSubjectExpansions {
			return nil, nil, nil, errors.New("grant subject budget exceeded")
		}
		for _, subject := range list {
			if !IsValidSubject(subject) {
				return nil, nil, nil, fmt.Errorf("invalid grant subject %q", subject)
			}
		}
	}
	pub, err := compileGrantPrefixRules(g.Pub.AllowPrefix)
	if err != nil {
		return nil, nil, nil, err
	}
	sub, err := compileGrantPrefixRules(g.Sub.AllowPrefix)
	if err != nil {
		return nil, nil, nil, err
	}
	perms := &Permissions{
		Publish:   &SubjectPermission{Allow: append([]string{}, g.Pub.Allow...), Deny: slices.Clone(g.Pub.Deny)},
		Subscribe: &SubjectPermission{Allow: append([]string{}, g.Sub.Allow...), Deny: slices.Clone(g.Sub.Deny)},
	}
	if g.Resp != nil {
		perms.Response = &ResponsePermission{MaxMsgs: g.Resp.MaxMsgs, Expires: g.Resp.Expires}
		validateResponsePermissions(perms)
	}
	return perms, pub, sub, nil
}

func (c *client) installAuthGrant(p *Permissions, pub, sub grantPrefixRules) {
	keepReplies := c.user != nil && c.user.Permissions != nil && sameResponsePermissions(c.user.Permissions.Response, p.Response)
	replies := c.replies
	c.user.Permissions = p
	c.user.defaultPerms = false
	c.setPermissions(p)
	if c.perms.sub.allow == nil {
		c.perms.sub.allow = NewSublistNoCache()
	}
	c.perms.pub.prefix, c.perms.sub.prefix = pub, sub
	if keepReplies {
		c.replies = replies
	} else if p.Response == nil {
		c.replies = nil
	}
	for _, sub := range c.subs {
		c.canSubscribe(string(sub.subject), string(sub.queue))
	}
}

func (c *client) setGrantExpiration(st *authGrantState) {
	c.clearAuthTimer()
	st.timerVersion++
	version := st.timerVersion
	expires := authverify.NarrowExpiry(st.jwtExpires, st.expires)
	deadline := st.deadline
	if expires != 0 {
		exp := time.Unix(expires, 0)
		if deadline.IsZero() || exp.Before(deadline) {
			deadline = exp
		}
	}
	c.expires = deadline
	if deadline.IsZero() {
		return
	}
	c.atmr = time.AfterFunc(time.Until(deadline), func() {
		c.mu.Lock()
		if c.isClosed() || c.authGrant != st || st.timerVersion != version {
			c.mu.Unlock()
			return
		}
		c.enqueueProto([]byte(fmt.Sprintf(errProto, "User Authentication Expired")))
		c.markConnAsClosed(AuthenticationExpired)
		c.mu.Unlock()
		c.closeConnection(AuthenticationExpired)
	})
}

func (c *client) finishGrantClose() {
	c.mu.Lock()
	if st := c.authGrant; st != nil {
		st.closeComplete = true
		c.notifyGrantClosed(st)
	}
	c.mu.Unlock()
}

func (c *client) notifyGrantClosed(st *authGrantState) {
	if !st.done || !st.closeComplete || st.closedNotified {
		return
	}
	st.closedNotified = true
	go st.hook.Closed(st.serverID, c.cid)
}

func (s *Server) grantClient(id uint64) *client {
	s.mu.RLock()
	c := s.clients[id]
	if c == nil {
		c = s.leafs[id]
	}
	s.mu.RUnlock()
	return c
}

// UpdateClientGrant replaces all permissions of an admitted grant connection.
// Invalid grants close the connection so removed rights cannot remain active.
func (s *Server) UpdateClientGrant(u authverify.GrantUpdate) error {
	c := s.grantClient(u.ClientID)
	if c == nil {
		return ErrUnknownClient
	}
	c.mu.Lock()
	st := c.authGrant
	if c.isClosed() {
		c.mu.Unlock()
		return ErrUnknownClient
	}
	if st == nil {
		c.mu.Unlock()
		return ErrNotGrantMode
	}
	if st.account != u.Account || st.user != u.UserNkey {
		c.mu.Unlock()
		return ErrUnknownClient
	}
	if u.Generation <= st.generation {
		c.mu.Unlock()
		return ErrStaleGeneration
	}
	grant := cloneAuthGrant(u.Grant)
	perms, pub, sub, err := compileAuthGrant(grant)
	if err != nil {
		c.markConnAsClosed(GrantRejected)
		c.mu.Unlock()
		c.closeConnection(GrantRejected)
		return ErrGrantRejected
	}
	if c.kind == LEAF {
		c.markConnAsClosed(AuthorizationChanged)
		c.mu.Unlock()
		c.closeConnection(AuthorizationChanged)
		return nil
	}
	st.grant, st.generation, st.expires = grant, u.Generation, u.Expires
	c.installAuthGrant(perms, pub, sub)
	c.setGrantExpiration(st)
	c.mu.Unlock()
	c.processSubsOnConfigReload(nil)
	return nil
}

// DisconnectClient closes a client or leaf with the protocol error for code.
func (s *Server) DisconnectClient(clientID uint64, code authverify.RejectCode) error {
	c := s.grantClient(clientID)
	if c == nil {
		return ErrUnknownClient
	}
	reason, message := GrantRejected, "Authorization Violation"
	if code == authverify.CodeResourceLimit {
		reason, message = ResourceLimit, "maximum connections exceeded"
	}
	c.sendErr(message)
	c.closeConnection(reason)
	return nil
}

// Leaf INFO can express only standard subjects. Advertise a superset to the
// remote and enforce the exact prefix rules on this hub in both directions.
func grantLeafWirePermission(p *SubjectPermission, rules grantPrefixRules) *SubjectPermission {
	if len(rules) == 0 {
		return p
	}
	wire := &SubjectPermission{Allow: slices.Clone(p.Allow), Deny: slices.Clone(p.Deny)}
	for _, rule := range rules {
		tokens := make([]string, len(rule))
		for i, token := range rule {
			tokens[i] = token.value
			if token.prefix {
				tokens[i] = "*"
			}
		}
		wire.Allow = append(wire.Allow, strings.Join(tokens, "."))
	}
	return wire
}

func (c *client) registerGrantUser(user *NkeyUser) error {
	if err := c.registerWithAccount(user.Account); err != nil {
		c.reportErrRegisterAccount(user.Account, err)
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed() {
		return ErrConnectionClosed
	}
	user.defaultPerms = false
	if c.authGrant != nil {
		user.Permissions = c.user.Permissions
		c.user = user
	} else {
		c.user = user
		p := &Permissions{Publish: &SubjectPermission{Allow: []string{}}, Subscribe: &SubjectPermission{Allow: []string{}}}
		c.installAuthGrant(p, nil, nil)
	}
	return nil
}

func (c *client) canAdvertiseLeafInterestInternal(subject string) bool {
	if c.canSubscribeInternal(subject) {
		return true
	}
	if c.authGrant == nil || c.isSolicitedLeafNode() || c.perms == nil {
		return false
	}
	if c.perms.resp != nil {
		return true
	}
	if !c.perms.sub.prefix.intersects(subject) {
		return false
	}
	if c.perms.sub.deny != nil && len(c.perms.sub.deny.Match(subject).psubs) > 0 {
		return false
	}
	return true
}

func (c *client) canAdvertiseLeafInterest(subject string) bool {
	if !c.canAdvertiseLeafInterestInternal(subject) {
		return false
	}
	c.loadMsgDenyFilterIfNeeded(subject, false)
	return true
}

func (c *client) canPublishGrantReply(subject string) bool {
	if c.kind == LEAF && c.authGrant != nil {
		return c.leafSendAllowed([]byte(subject))
	}
	return c.pubAllowedFullCheck(subject, true, true)
}

func (c *client) leafSubscriptionAllowed(subject string) bool {
	literal := subjectIsLiteral(subject)
	if !literal && c.authGrant == nil {
		return true
	}
	if c.pubAllowedFullCheck(subject, true, true) {
		return true
	}
	if literal || c.perms == nil || c.perms.pub.allow == nil {
		return false
	}
	if c.perms.pub.deny != nil && c.perms.pub.deny.HasInterest(subject) {
		return false
	}
	return len(c.perms.pub.allow.ReverseMatch(subject).psubs) > 0
}
