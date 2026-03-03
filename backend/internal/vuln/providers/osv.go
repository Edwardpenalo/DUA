package providers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type OSVQuery struct {
	Version string `json:"version"`
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
}

type OSVResp struct {
	Vulns []struct {
		ID       string `json:"id"`
		Summary  string `json:"summary"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
	} `json:"vulns"`
}

func QueryOSV(ecosystem, name, version string, timeout time.Duration) (*OSVResp, error) {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}

	var q OSVQuery
	q.Version = version
	q.Package.Ecosystem = ecosystem
	q.Package.Name = name

	b, _ := json.Marshal(q)

	req, _ := http.NewRequest(http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	c := &http.Client{Timeout: timeout}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out OSVResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
