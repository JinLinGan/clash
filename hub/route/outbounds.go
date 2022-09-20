package route

import (
	"net/http"

	"github.com/Dreamacro/clash/config"

	C "github.com/Dreamacro/clash/constant"

	T "github.com/Dreamacro/clash/tunnel"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func outbounds() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getOutbounds)
	r.Post("/", addOutbounds)
	r.Delete("/", deleteOutbounds)
	return r
}

func getOutbounds(w http.ResponseWriter, r *http.Request) {
	proxies := T.Proxies()
	render.JSON(w, r, render.M{
		"proxies": proxies,
	})
}

func addOutbounds(w http.ResponseWriter, r *http.Request) {
	var params []config.ProxyConfig

	err := render.DecodeJSON(r.Body, &params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	var ps []C.Proxy
	for _, param := range params {
		if proxy, err := config.ParseProxy(param); err != nil {
			ps = append(ps, proxy)
		}
	}

	err = T.AddOutbounds(ps)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func deleteOutbounds(w http.ResponseWriter, r *http.Request) {
	var params []string
	err := render.DecodeJSON(r.Body, &params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	T.DeleteOutbounds(params)
	render.NoContent(w, r)
}
