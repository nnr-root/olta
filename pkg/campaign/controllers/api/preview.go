package api

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/s4l1hs/olta/pkg/campaign/bitb"
	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/personalizer"
)

const (
	previewVariationCount = 5
	maxPreviewRequestSize = 2 << 20
)

type PersonalizerPreviewRequest struct {
	Subject string               `json:"subject"`
	Text    string               `json:"text"`
	HTML    string               `json:"html"`
	Context personalizer.Context `json:"context"`
}

type PersonalizerVariation struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

type PersonalizerPreviewResponse struct {
	Variations []PersonalizerVariation `json:"variations"`
}

// PersonalizerPreview returns five independently expanded message variants.
func (as *Server) PersonalizerPreview(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		JSONResponse(writer, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxPreviewRequestSize)
	var payload PersonalizerPreviewRequest
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(&payload); err != nil || ensureJSONEOF(decoder) != nil {
		JSONResponse(writer, models.Response{Success: false, Message: "Invalid personalizer preview request"}, http.StatusBadRequest)
		return
	}
	engine := personalizer.New(personalizer.Options{EnableSpintax: true})
	response := PersonalizerPreviewResponse{Variations: make([]PersonalizerVariation, 0, previewVariationCount)}
	for index := 0; index < previewVariationCount; index++ {
		subject, err := engine.Personalize(payload.Subject, payload.Context)
		if err != nil {
			JSONResponse(writer, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
			return
		}
		textBody, err := engine.Personalize(payload.Text, payload.Context)
		if err != nil {
			JSONResponse(writer, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
			return
		}
		htmlBody, err := engine.Personalize(payload.HTML, payload.Context)
		if err != nil {
			JSONResponse(writer, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
			return
		}
		response.Variations = append(response.Variations, PersonalizerVariation{Subject: subject, Text: textBody, HTML: htmlBody})
	}
	JSONResponse(writer, response, http.StatusOK)
}

type BITBPreviewRequest struct {
	URL     string     `json:"url"`
	Title   string     `json:"title"`
	Theme   bitb.Theme `json:"theme"`
	Content string     `json:"content"`
}

type BITBPreviewResponse struct {
	URL   string     `json:"url"`
	Theme bitb.Theme `json:"theme"`
	HTML  string     `json:"html"`
}

// BITBPreview renders an exact theme preview for the authenticated editor.
func (as *Server) BITBPreview(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		JSONResponse(writer, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxPreviewRequestSize)
	var payload BITBPreviewRequest
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(&payload); err != nil || ensureJSONEOF(decoder) != nil {
		JSONResponse(writer, models.Response{Success: false, Message: "Invalid BITB preview request"}, http.StatusBadRequest)
		return
	}
	payload.URL = strings.TrimSpace(payload.URL)
	if payload.URL == "" {
		payload.URL = "https://login.example.test/"
	}
	frame := bitb.NewFrame(payload.URL)
	frame.Theme = payload.Theme
	frame.Title = payload.Title
	// Preview content is isolated by the dashboard in a sandboxed iframe.
	frame.Content = template.HTML(payload.Content)
	rendered, err := bitb.RenderFrame(frame)
	if err != nil {
		JSONResponse(writer, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
		return
	}
	JSONResponse(writer, BITBPreviewResponse{URL: payload.URL, Theme: payload.Theme, HTML: string(rendered)}, http.StatusOK)
}

// NewPreviewHandler exposes the two preview routes without authentication for
// isolated handler tests. Production mounts the same handlers behind API auth.
func NewPreviewHandler() http.Handler {
	server := new(Server)
	router := mux.NewRouter()
	router.HandleFunc("/api/v1/personalizer/preview", server.PersonalizerPreview).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/bitb/preview", server.BITBPreview).Methods(http.MethodPost)
	return router
}
