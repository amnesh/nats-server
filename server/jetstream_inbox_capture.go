// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0.

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
)

const InboxCaptureSubject = "_INBOX.>"

var (
	ErrJSStreamInboxCapture          = errors.New("stream configuration captures inbox subjects")
	ErrJSSourceDeliverSubjectChanged = errors.New("consumer create response changed the delivery subject")
)

type inboxCaptureField struct {
	field   string
	subject string
}

// inboxCaptureFields walks normalized configuration in a stable field order.
func inboxCaptureFields(cfg *StreamConfig) []inboxCaptureField {
	if cfg == nil {
		return nil
	}
	var found []inboxCaptureField
	add := func(field, subject string) {
		if subject != _EMPTY_ && SubjectsCollide(subject, InboxCaptureSubject) {
			found = append(found, inboxCaptureField{field, subject})
		}
	}
	for i, subject := range cfg.Subjects {
		add(fmt.Sprintf("subjects[%d]", i), subject)
	}
	source := func(prefix string, src *StreamSource) {
		if src == nil {
			return
		}
		if src.External != nil && src.External.DeliverPrefix != _EMPTY_ {
			add(prefix+".external.deliver", src.External.DeliverPrefix+".>")
		}
		if src.Consumer != nil {
			add(prefix+".consumer.deliver_subject", src.Consumer.DeliverSubject)
		}
	}
	source("mirror", cfg.Mirror)
	for i, src := range cfg.Sources {
		source(fmt.Sprintf("sources[%d]", i), src)
	}
	return found
}

func streamInboxCapture(cfg *StreamConfig) (field, subject string, found bool) {
	if fields := inboxCaptureFields(cfg); len(fields) > 0 {
		return fields[0].field, fields[0].subject, true
	}
	return _EMPTY_, _EMPTY_, false
}

func (s *Server) inboxCaptureExempt(ci *ClientInfo) bool {
	return ci != nil && ci.InProcessUnrestricted && ci.Service == _EMPTY_
}

func inboxCaptureError(field, subject string) *ApiError {
	return NewJSStreamInvalidConfigError(fmt.Errorf("%w: %s %q", ErrJSStreamInboxCapture, field, subject))
}

func (s *Server) checkStreamInboxCapture(ci *ClientInfo, cfg *StreamConfig) *ApiError {
	js := s.getJetStream()
	if js == nil || !js.rejectInboxCapture || s.inboxCaptureExempt(ci) {
		return nil
	}
	if field, subject, found := streamInboxCapture(cfg); found {
		return inboxCaptureError(field, subject)
	}
	return nil
}

// restoreInboxGate freezes admission facts. No later request metadata can change them.
type restoreInboxGate struct {
	exempt   bool
	admitted *StreamConfig
}

// cloneInboxCaptureConfig keeps the full config private, including nested source fields.
func cloneInboxCaptureConfig(cfg *StreamConfig) *StreamConfig {
	if cfg == nil {
		return nil
	}
	value := *cfg
	cp := &value
	if cfg.Placement != nil {
		placement := *cfg.Placement
		cp.Placement = &placement
	}
	if cfg.SubjectTransform != nil {
		transform := *cfg.SubjectTransform
		cp.SubjectTransform = &transform
	}
	if cfg.RePublish != nil {
		republish := *cfg.RePublish
		cp.RePublish = &republish
	}
	cp.Metadata = maps.Clone(cfg.Metadata)
	cp.Subjects = slices.Clone(cfg.Subjects)
	if cfg.Placement != nil {
		cp.Placement.Tags = slices.Clone(cfg.Placement.Tags)
	}
	copySource := func(src *StreamSource) *StreamSource {
		if src == nil {
			return nil
		}
		clone := *src
		clone.SubjectTransforms = slices.Clone(src.SubjectTransforms)
		if src.External != nil {
			ext := *src.External
			clone.External = &ext
		}
		if src.Consumer != nil {
			consumer := *src.Consumer
			clone.Consumer = &consumer
		}
		if src.OptStartTime != nil {
			start := *src.OptStartTime
			clone.OptStartTime = &start
		}
		return &clone
	}
	cp.Mirror = copySource(cfg.Mirror)
	cp.Sources = make([]*StreamSource, len(cfg.Sources))
	for i, src := range cfg.Sources {
		cp.Sources[i] = copySource(src)
	}
	return cp
}

func (s *Server) newRestoreInboxGate(ci *ClientInfo, admitted *StreamConfig) (restoreInboxGate, *ApiError) {
	if err := s.checkStreamInboxCapture(ci, admitted); err != nil {
		return restoreInboxGate{}, err
	}
	return restoreInboxGate{exempt: s.inboxCaptureExempt(ci), admitted: cloneInboxCaptureConfig(admitted)}, nil
}

func restoreInboxGateFromAssignment(sa *streamAssignment) restoreInboxGate {
	return restoreInboxGate{exempt: sa.RestoreInboxExempt, admitted: cloneInboxCaptureConfig(sa.Config)}
}

func (js *jetStream) checkRestoredInboxCapture(g restoreInboxGate, final *StreamConfig) error {
	if js == nil || !js.rejectInboxCapture || g.exempt {
		return nil
	}
	admitted := inboxCaptureFields(g.admitted)
	for _, field := range inboxCaptureFields(final) {
		if !slices.Contains(admitted, field) {
			return inboxCaptureError(field.field, field.subject)
		}
	}
	return nil
}

func (s *Server) checkSourceDeliverSubject(want, got string) error {
	js := s.getJetStream()
	if js == nil || !js.rejectInboxCapture || want == got {
		return nil
	}
	return fmt.Errorf("%w: requested %q, response %q", ErrJSSourceDeliverSubjectChanged, want, got)
}

// inProcessUnrestricted reads the authenticated origin and its current authority.
// Empty permission trees are still restrictions, including an empty grant.
func (c *client) inProcessUnrestricted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.kind != CLIENT || !c.iproc {
		return false
	}
	p := c.perms
	return p == nil || (p.pub.allow == nil && p.pub.deny == nil && p.sub.allow == nil && p.sub.deny == nil)
}

// clearForwardedOriginMarker removes caller-supplied proof before any delivery
// or forwarding. Routes and gateways carry proof from trusted servers unchanged.
func (c *client) clearForwardedOriginMarker(msg []byte) []byte {
	if (c.kind != CLIENT && c.kind != LEAF) || c.pa.hdr <= 0 || c.pa.hdr > len(msg) {
		return msg
	}
	var ci ClientInfo
	if err := json.Unmarshal(sliceHeader(ClientInfoHdr, msg[:c.pa.hdr]), &ci); err != nil || !ci.InProcessUnrestricted {
		return msg
	}
	ci.InProcessUnrestricted = false
	b, err := json.Marshal(&ci)
	if err != nil {
		return msg
	}
	return c.setHeader(ClientInfoHdr, bytesToString(b), msg)
}
