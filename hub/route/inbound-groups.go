package route

import (
	"net/http"

	"github.com/Dreamacro/clash/adapter/outboundgroup"
	T "github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func outboundGroups() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getOutbounds)
	r.Post("/", addOutboudGroups)
	r.Delete("/", deleteOutbounds)
	return r
}

func addOutboudGroups(w http.ResponseWriter, r *http.Request) {
	var params []outboundgroup.GroupCommonOption
	err := render.DecodeJSON(r.Body, &params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	err = T.AddOutboundGroups(params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}
