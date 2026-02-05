package oidc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/luikyv/go-oidc/internal/joseutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func (ctx Context) SSFJWKS() (goidc.JSONWebKeySet, error) {
	return ctx.SSFJWKSFunc(ctx)
}

func (ctx Context) SSFPublicJWKS() (goidc.JSONWebKeySet, error) {
	jwks, err := ctx.SSFJWKS()
	if err != nil {
		return goidc.JSONWebKeySet{}, err
	}

	return jwks.Public(), nil
}

func (ctx Context) SSFCreateEventStream(stream *goidc.SSFEventStream) error {
	return ctx.SSFEventStreamManager.Create(ctx, stream)
}

func (ctx Context) SSFUpdateEventStream(stream *goidc.SSFEventStream) error {
	return ctx.SSFEventStreamManager.Update(ctx, stream)
}

func (ctx Context) SSFEventStream(id string) (*goidc.SSFEventStream, error) {
	return ctx.SSFEventStreamManager.EventStream(ctx, id)
}

func (ctx Context) SSFEventStreams(receiverID string) ([]*goidc.SSFEventStream, error) {
	return ctx.SSFEventStreamManager.EventStreams(ctx, receiverID)
}

func (ctx Context) SSFDeleteEventStream(id string) error {
	return ctx.SSFEventStreamManager.Delete(ctx, id)
}

func (ctx Context) SSFAddSubject(id string, subject goidc.SSFSubject, opts goidc.SSFSubjectOptions) error {
	return ctx.SSFEventStreamSubjectManager.Add(ctx, id, subject, opts)
}

func (ctx Context) SSFRemoveSubject(id string, subject goidc.SSFSubject) error {
	return ctx.SSFEventStreamSubjectManager.Remove(ctx, id, subject)
}

func (ctx Context) SSFEventStreamID() string {
	if ctx.SSFEventStreamIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.SSFEventStreamIDFunc(ctx.Context())
}

func (ctx Context) SSFAuthenticatedReceiver() (goidc.SSFReceiver, error) {
	if ctx.SSFAuthenticatedReceiverFunc == nil {
		return goidc.SSFReceiver{}, errors.New("authenticated receiver function is not defined")
	}

	return ctx.SSFAuthenticatedReceiverFunc(ctx.Request)
}

func (ctx Context) SSFIsEventStreamStatusReadAllowed(_ goidc.SSFReceiver) bool {
	return true
}

func (ctx Context) SSFIsEventStreamStatusWriteAllowed(_ goidc.SSFReceiver) bool {
	return true
}

func (ctx Context) SSFJWTID() string {
	if ctx.SSFJWTIDFunc == nil {
		return uuid.NewString()
	}

	return ctx.SSFJWTIDFunc(ctx.Context())
}

func (ctx Context) SSFSign(claims any, opts *jose.SignerOptions) (string, error) {

	if ctx.SSFSignerFunc == nil {
		jwk, err := ctx.SSFJWKByAlg(ctx.SSFSignatureAlgorithm)
		if err != nil {
			return "", fmt.Errorf("could not load the signing jwk: %w", err)
		}
		return joseutil.Sign(claims, jose.SigningKey{Algorithm: ctx.SSFSignatureAlgorithm, Key: jwk}, opts)
	}

	keyID, key, err := ctx.SSFSignerFunc(ctx, ctx.SSFSignatureAlgorithm)
	if err != nil {
		return "", fmt.Errorf("could not load the signer: %w", err)
	}

	return joseutil.Sign(claims, jose.SigningKey{
		Algorithm: ctx.SSFSignatureAlgorithm,
		Key: joseutil.OpaqueSigner{
			ID:        keyID,
			Algorithm: ctx.SSFSignatureAlgorithm,
			Signer:    key,
		},
	}, opts)
}

func (ctx Context) SSFJWKByAlg(alg goidc.SignatureAlgorithm) (goidc.JSONWebKey, error) {
	jwks, err := ctx.SSFJWKS()
	if err != nil {
		return goidc.JSONWebKey{}, err
	}

	return jwks.KeyByAlg(string(alg))
}

func (ctx Context) SSFSaveEvent(streamID string, event goidc.SSFEvent) error {
	return ctx.SSFEventPollManager.Save(ctx, streamID, event)
}

func (ctx Context) SSFPollEvents(streamID string, opts goidc.SSFPollOptions) (goidc.SSFEvents, error) {
	return ctx.SSFEventPollManager.Poll(ctx, streamID, opts)
}

func (ctx Context) SSFAcknowledgeEvents(streamID string, jtis []string, opts goidc.SSFAcknowledgementOptions) error {
	return ctx.SSFEventPollManager.Acknowledge(ctx, streamID, jtis, opts)
}

func (ctx Context) SSFAcknowledgeErrors(streamID string, errs map[string]goidc.SSFEventError, opts goidc.SSFAcknowledgementOptions) error {
	return ctx.SSFEventPollManager.AcknowledgeErrors(ctx, streamID, errs, opts)
}

func (ctx Context) SSFTriggerVerificationEvent(streamID string, opts goidc.SSFStreamVerificationOptions) error {
	return ctx.SSFEventStreamVerificationManager.Trigger(ctx, streamID, opts)
}

func (ctx Context) SSFHTTPClient() *http.Client {
	if ctx.SSFHTTPClientFunc == nil {
		return http.DefaultClient
	}

	return ctx.SSFHTTPClientFunc(ctx)
}
