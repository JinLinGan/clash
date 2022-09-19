package route

import (
	"net/http"

	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/controller"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func inbounds() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getInbounds)
	r.Post("/", addInbounds)
	r.Delete("/", deleteInbounds)
	return r
}

func getInbounds(w http.ResponseWriter, r *http.Request) {
	inbounds := controller.GetInbounds()
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

func addInbounds(w http.ResponseWriter, r *http.Request) {
	var params []config.InboundConfig
	err := render.DecodeJSON(r.Body, &params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	err = controller.AddInbounds(params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func deleteInbounds(w http.ResponseWriter, r *http.Request) {
	var params []string
	err := render.DecodeJSON(r.Body, &params)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	controller.DeleteInbounds(params)
	render.NoContent(w, r)
}
