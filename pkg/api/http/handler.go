package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"os/exec"
	"strings"

	"github.com/gorilla/mux"

	"Proxy/pkg/domain/models"
	"Proxy/pkg/repository/mongodb"
)

var payloads = []string{
	";cat /etc/passwd;",
	"|cat /etc/passwd|",
	"`cat /etc/passwd`",
}

type Handler struct {
	Repo *mongodb.RequestRepository
}

func NewHandler(repo *mongodb.RequestRepository) *Handler {
	return &Handler{
		Repo: repo,
	}
}

// HandleGetAllRequests
// @Summary Get all requests
// @Description Возвращает список всех запросов, сохраненных в базе данных
// @Tags requests
// @Produce json
// @Success 200 {array} models.RequestResponse
// @Failure 500 {string} string "Failed to fetch requests"
// @Router /api/v1/requests [get]
func (h *Handler) HandleGetAllRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := h.Repo.GetAllRequests(context.TODO())
	if err != nil {
		http.Error(w, "Failed to fetch requests", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(requests)
}

// HandleGetRequestByID
// @Summary Get request by ID
// @Description Возвращает конкретный запрос по его ID
// @Tags requests
// @Param id path string true "Request ID"
// @Produce json
// @Success 200 {object} models.RequestResponse
// @Failure 400 {string} string "Invalid request ID"
// @Failure 404 {string} string "Request not found"
// @Router /api/v1/requests/{id} [get]
func (h *Handler) HandleGetRequestByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		http.Error(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	request, err := h.Repo.GetRequestByID(context.TODO(), id)
	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(request)
}

// HandleRepeatRequest
// @Summary Repeat a request by ID
// @Description Повторно отправляет запрос, сохраненный по его ID, и возвращает результат
// @Tags requests
// @Param id path string true "Request ID"
// @Produce json
// @Success 200 {object} models.ParsedResponse
// @Failure 400 {string} string "Invalid request ID"
// @Failure 404 {string} string "Request not found"
// @Failure 500 {string} string "Failed to repeat request"
// @Router /api/v1/repeat/{id} [post]
func (h *Handler) HandleRepeatRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		http.Error(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	reqResp, err := h.Repo.GetRequestByID(context.TODO(), id)
	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	res, err := execute(reqResp)
	if err != nil {
		http.Error(w, "Failed to execute request", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(res)
}

func execute(request *models.RequestResponse) (string, error) {
	var curlCommand bytes.Buffer

	curlCommand.WriteString("curl -x http://go-app-8080:8080 ")
	if request.Request.Method != "CONNECT" {
		curlCommand.WriteString("-X ")
		curlCommand.WriteString(request.Request.Method)
	}

	for key, value := range request.Request.GetParams {
		curlCommand.WriteString(fmt.Sprintf(" -G --data-urlencode \"%s=%s\"", key, value))
	}

	for key, value := range request.Request.PostParams {
		curlCommand.WriteString(fmt.Sprintf(" -d \"%s=%s\"", key, value))
	}

	for key, value := range request.Request.Headers {
		curlCommand.WriteString(fmt.Sprintf(" -H \"%s: %s\"", key, value))
	}

	for key, value := range request.Request.Cookies {
		curlCommand.WriteString(fmt.Sprintf(" --cookie \"%s=%s\"", key, value))
	}

	curlCommand.WriteString(" " + request.Request.Path)

	s := curlCommand.String()
	cmd := exec.Command("bash", "-c", s)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ошибка при выполнении команды curl: %v, вывод: %s", err, out)
	}

	res := strings.Split(string(out), "<html>")
	result := strings.Join(res[len(res)-1:], "<html>")
	return "<html>" + result, nil
}

// HandleScanRequest
// @Summary Scan request by ID for vulnerabilities
// @Description Проверяет запрос по его ID на уязвимости Command Injection
// @Tags requests
// @Param id path string true "Request ID"
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 400 {string} string "Invalid request ID"
// @Failure 404 {string} string "Request not found"
// @Router /api/v1/scan/{id} [get]
func (h *Handler) HandleScanRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		http.Error(w, "Invalid request ID", http.StatusBadRequest)
		return
	}

	reqResp, err := h.Repo.GetRequestByID(context.TODO(), id)
	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	vulnerabilities, err := checkCommandInjection(reqResp)
	if err != nil {
		http.Error(w, "Error checking vulnerabilities", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  200,
		"message": "success",
		"payload": vulnerabilities,
	}
	json.NewEncoder(w).Encode(response)
}

func checkCommandInjection(request *models.RequestResponse) ([]string, error) {
	var results []string

	parameters := map[string]map[string]string{
		"GET":     request.Request.GetParams,
		"POST":    request.Request.PostParams,
		"Headers": request.Request.Headers,
		"Cookies": request.Request.Cookies,
	}

	for paramType, params := range parameters {
		for key, _ := range params {
			for _, payload := range payloads {
				modifiedRequest := modifyRequest(request, paramType, key, payload)
				modifiedResponse, err := execute(modifiedRequest)
				if err != nil {
					//return results, err
					continue
				}

				if strings.Contains(modifiedResponse, "root:") {
					results = append(results, fmt.Sprintf("Параметр '%s' уязвим для Command Injection с полезной нагрузкой '%s'\n", key, payload))
				}
			}
		}
	}

	if len(results) == 0 {
		return []string{"всё хорошо :)"}, nil
	}
	return results, nil
}

func modifyRequest(request *models.RequestResponse, paramType, key, payload string) *models.RequestResponse {
	modifiedRequest := request

	switch paramType {
	case "GET":
		modifiedRequest.Request.GetParams[key] += payload
	case "POST":
		modifiedRequest.Request.PostParams[key] += payload
	case "Headers":
		modifiedRequest.Request.Headers[key] += payload
	case "Cookies":
		modifiedRequest.Request.Cookies[key] += payload
	}
	return modifiedRequest
}
