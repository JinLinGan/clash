package route

import (
	"net/http"

	"github.com/Dreamacro/clash/config"
	T "github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ruleRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRules)
	r.Put("/", updateRules)
	return r
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

func getRules(w http.ResponseWriter, r *http.Request) {
	rawRules := T.Rules()

	var rules []Rule
	for _, rule := range rawRules {
		rules = append(rules, Rule{
			Type:    rule.RuleType().String(),
			Payload: rule.Payload(),
			Proxy:   rule.Adapter(),
		})
	}

	render.JSON(w, r, render.M{
		"rules": rules,
	})
}

func updateRules(w http.ResponseWriter, r *http.Request) {
	var params []config.RuleConfig
	rules, err := config.ParseRules(params, T.Proxies())
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	T.UpdateRules(rules)
	render.NoContent(w, r)
}
