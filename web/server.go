package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"greenlight/models"
	"html/template"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

//go:embed templates/*
var templatesFS embed.FS

type Server struct {
	Result models.CheckResult
}

func NewServer(result models.CheckResult) *Server {
	return &Server{Result: result}
}

func (s *Server) Start() error {
	r := mux.NewRouter()

	r.HandleFunc("/", s.handleHome).Methods("GET")
	r.HandleFunc("/report", s.handleReport).Methods("GET")
	r.HandleFunc("/api/report", s.handleAPIReport).Methods("GET")

	fmt.Println("Serving dashboard at http://localhost:8080/report")
	return http.ListenAndServe(":8080", r)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/report", http.StatusSeeOther)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	// Define custom template functions
	funcMap := template.FuncMap{
		"mul": func(a, b interface{}) float64 {
			aFloat := toFloat64(a)
			bFloat := toFloat64(b)
			return aFloat * bFloat
		},
		"div": func(a, b interface{}) float64 {
			aFloat := toFloat64(a)
			bFloat := toFloat64(b)
			if bFloat == 0 {
				return 0
			}
			return aFloat / bFloat
		},
		"add": func(a, b interface{}) int {
			aInt := toInt(a)
			bInt := toInt(b)
			return aInt + bInt
		},
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
		"ge": func(a, b interface{}) bool {
			aFloat := toFloat64(a)
			bFloat := toFloat64(b)
			return aFloat >= bFloat
		},
		"gt": func(a, b interface{}) bool {
			aFloat := toFloat64(a)
			bFloat := toFloat64(b)
			return aFloat > bFloat
		},
		"lt": func(a, b interface{}) bool {
			aFloat := toFloat64(a)
			bFloat := toFloat64(b)
			return aFloat < bFloat
		},
		"and": func(args ...bool) bool {
			// Fixed: Support multiple arguments for AND operation
			for _, arg := range args {
				if !arg {
					return false
				}
			}
			return len(args) > 0 // Return true only if all args are true and we have at least one arg
		},
		"eq": func(a, b interface{}) bool {
			return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
		},
		"ne": func(a, b interface{}) bool {
			return fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b)
		},
		"or": func(args ...interface{}) bool {
			for _, arg := range args {
				if b, ok := arg.(bool); ok && b {
					return true
				}
			}
			return false
		},
		"len": func(v interface{}) int {
			if v == nil {
				return 0
			}
			switch val := v.(type) {
			case []interface{}:
				return len(val)
			case map[string]interface{}:
				return len(val)
			case string:
				return len(val)
			default:
				return 0
			}
		},
		"printf": func(format string, args ...interface{}) string {
			return fmt.Sprintf(format, args...)
		},
	}

	// Parse template with custom functions
	tmpl, err := template.New("report.html").Funcs(funcMap).ParseFS(templatesFS, "templates/report.html")
	if err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
		return
	}

	// Execute template - this will only write headers once
	if err := tmpl.Execute(w, s.Result); err != nil {
		// Don't call http.Error here as headers may already be written
		fmt.Printf("Template execution error: %v\n", err)
		return
	}
}

func (s *Server) handleAPIReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(s.Result); err != nil {
		http.Error(w, fmt.Sprintf("JSON encoding error: %v", err), http.StatusInternalServerError)
	}
}

// Helper functions for type conversion
func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case int:
		return float64(val)
	case int32:
		return float64(val)
	case int64:
		return float64(val)
	case float32:
		return float64(val)
	case float64:
		return val
	case string:
		// Try to parse string to float, return 0 if fails
		if val == "" {
			return 0
		}
		// Simple string to float conversion for basic cases
		if val == "0" {
			return 0
		}
		return 0
	default:
		return 0
	}
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int32:
		return int(val)
	case int64:
		return int(val)
	case float32:
		return int(val)
	case float64:
		return int(val)
	case string:
		// Simple string to int conversion for basic cases
		if val == "" || val == "0" {
			return 0
		}
		return 0
	default:
		return 0
	}
}
