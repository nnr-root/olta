package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/s4l1hs/olta/pkg/campaign/models"
	"github.com/s4l1hs/olta/pkg/campaign/quishing"
)

const maxQRPreviewRequestSize = 16 << 10

// QRCodePreviewRequest describes a dashboard QR preview request.
type QRCodePreviewRequest struct {
	URL             string                   `json:"url"`
	Size            int                      `json:"size"`
	BackgroundColor string                   `json:"background_color"`
	ForegroundColor string                   `json:"foreground_color"`
	ErrorCorrection quishing.ErrorCorrection `json:"error_correction"`
}

// QRCodePreviewResponse contains browser preview data and inline MIME metadata.
type QRCodePreviewResponse struct {
	URL         string           `json:"url"`
	Base64      string           `json:"base64"`
	DataURI     string           `json:"data_uri"`
	Filename    string           `json:"filename"`
	ContentID   string           `json:"content_id"`
	ContentType string           `json:"content_type"`
	Options     quishing.Options `json:"options"`
}

// QRCodePreview generates an in-memory QR preview for the web dashboard.
func (as *Server) QRCodePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxQRPreviewRequestSize)
	var request QRCodePreviewRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid QR preview request"}, http.StatusBadRequest)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid QR preview request"}, http.StatusBadRequest)
		return
	}

	generated, err := quishing.NewService().Generate(request.URL, quishing.Options{
		Size:            request.Size,
		BackgroundColor: request.BackgroundColor,
		ForegroundColor: request.ForegroundColor,
		ErrorCorrection: request.ErrorCorrection,
	})
	if err != nil {
		JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
		return
	}

	JSONResponse(w, QRCodePreviewResponse{
		URL:         request.URL,
		Base64:      generated.Base64,
		DataURI:     generated.DataURI,
		Filename:    generated.Attachment.Filename,
		ContentID:   generated.Attachment.ContentID,
		ContentType: generated.Attachment.ContentType,
		Options:     generated.Options,
	}, http.StatusOK)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}
