package ssf

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if !config.SSFIsEnabled {
		return
	}

	router.Handle("GET /.well-known/ssf-configuration",
		goidc.ApplyMiddlewares(oidc.Handler(config, handleConfiguration), middlewares...))
	router.Handle("GET "+config.EndpointPrefix+config.SSFJWKSEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleJWKS), middlewares...))

	router.Handle("POST "+config.EndpointPrefix+config.SSFConfigurationEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleCreateStream), middlewares...))
	router.Handle("PUT "+config.EndpointPrefix+config.SSFConfigurationEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleUpdateStream), middlewares...))
	router.Handle("PATCH "+config.EndpointPrefix+config.SSFConfigurationEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handlePatchStream), middlewares...))
	router.Handle("GET "+config.EndpointPrefix+config.SSFConfigurationEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleFetchStream), middlewares...))
	router.Handle("DELETE "+config.EndpointPrefix+config.SSFConfigurationEndpoint,
		goidc.ApplyMiddlewares(oidc.Handler(config, handleDeleteStream), middlewares...))

	if config.SSFIsStatusManagementEnabled {
		router.Handle("GET "+config.EndpointPrefix+config.SSFStatusEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleFetchStreamStatus), middlewares...))
		router.Handle("POST "+config.EndpointPrefix+config.SSFStatusEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleUpdateStreamStatus), middlewares...))
	}

	if config.SSFIsSubjectManagementEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.SSFAddSubjectEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleAddSubject), middlewares...))
		router.Handle("POST "+config.EndpointPrefix+config.SSFRemoveSubjectEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleRemoveSubject), middlewares...))
	}

	if slices.Contains(config.SSFDeliveryMethods, goidc.SSFDeliveryMethodPoll) {
		router.Handle("POST "+config.EndpointPrefix+config.SSFPollingEndpoint+"/{stream_id}",
			goidc.ApplyMiddlewares(oidc.Handler(config, handlePollEvents), middlewares...))
	}

	if config.SSFIsVerificationEnabled {
		router.Handle("POST "+config.EndpointPrefix+config.SSFVerificationEndpoint,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleCreateVerificationEvent), middlewares...))
	}
}

func handleConfiguration(ctx oidc.Context) {
	configuration := newConfiguration(ctx)
	if err := ctx.Write(configuration, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleJWKS(ctx oidc.Context) {
	jwks, err := ctx.SSFPublicJWKS()
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(jwks, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleCreateStream(ctx oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	stream, err := createStream(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(stream, http.StatusCreated); err != nil {
		ctx.WriteError(err)
	}
}

func handleUpdateStream(ctx oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	stream, err := updateStream(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(stream, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handlePatchStream(ctx oidc.Context) {
	var req request
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	stream, err := patchStream(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(stream, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleFetchStream(ctx oidc.Context) {
	if streamID := ctx.Request.URL.Query().Get("stream_id"); streamID != "" {
		stream, err := fetchStream(ctx, streamID)
		if err != nil {
			ctx.WriteError(err)
			return
		}

		if err := ctx.Write(stream, http.StatusOK); err != nil {
			ctx.WriteError(err)
		}
		return
	}

	streams, err := fetchStreams(ctx)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(streams, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleDeleteStream(ctx oidc.Context) {
	streamID := ctx.Request.URL.Query().Get("stream_id")
	if streamID == "" {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream_id is required"))
		return
	}

	err := deleteStream(ctx, streamID)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.WriteStatus(http.StatusNoContent)
}

func handleFetchStreamStatus(ctx oidc.Context) {
	streamID := ctx.Request.URL.Query().Get("stream_id")
	if streamID == "" {
		ctx.WriteError(goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream_id is required"))
		return
	}

	status, err := fetchStreamStatus(ctx, streamID)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(status, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleUpdateStreamStatus(ctx oidc.Context) {
	var req requestStatus
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	status, err := updateStreamStatus(ctx, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(status, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleAddSubject(ctx oidc.Context) {
	var req requestSubject
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	if err := addSubject(ctx, req); err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.WriteStatus(http.StatusOK)
}

func handleRemoveSubject(ctx oidc.Context) {
	var req requestSubject
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	if err := removeSubject(ctx, req); err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.WriteStatus(http.StatusNoContent)
}

func handlePollEvents(ctx oidc.Context) {
	var req requestPollEvents
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	streamID := ctx.Request.PathValue("stream_id")
	events, err := pollEvents(ctx, streamID, req)
	if err != nil {
		ctx.WriteError(err)
		return
	}

	if err := ctx.Write(events, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleCreateVerificationEvent(ctx oidc.Context) {
	var req requestVerificationEvent
	if err := json.NewDecoder(ctx.Request.Body).Decode(&req); err != nil {
		ctx.WriteError(goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not parse the request", err))
		return
	}

	if err := scheduleVerificationEvent(ctx, req); err != nil {
		ctx.WriteError(err)
		return
	}

	ctx.WriteStatus(http.StatusNoContent)
}
