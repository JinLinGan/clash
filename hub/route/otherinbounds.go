package route

import (
	"net/http"

	"github.com/Dreamacro/clash/config"
	P "github.com/Dreamacro/clash/listener"
	"github.com/Dreamacro/clash/log"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func otherInbounds() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getOtherInbounds)
	r.Post("/", addOtherInbounds)
	r.Delete("/", deleteOtherInbounds)
	return r
}

func getOtherInbounds(w http.ResponseWriter, r *http.Request) {
	inbounds := P.GetOtherInbounds()
	var result []map[string]interface{}
	for _, inbound := range inbounds {
		result = append(result, map[string]interface{}{
			"name":       inbound.Name(),
			"type":       inbound.Type(),
			"rawAddress": inbound.RawAddress(),
		})
	}
	render.JSON(w, r, result)
}

func addOtherInbounds(w http.ResponseWriter, r *http.Request) {
	var params []config.OtherInbound
	err := render.DecodeJSON(r.Body, &params)
	if err != nil {
		log.Errorln(err.Error())
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	err = P.AddOtherInbounds(params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func deleteOtherInbounds(w http.ResponseWriter, r *http.Request) {
	var params []string
	err := render.DecodeJSON(r.Body, &params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	P.DeleteOtherInbound(params)
	render.NoContent(w, r)
}
