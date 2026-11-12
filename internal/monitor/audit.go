package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/models"
)

// auditEntry is a minimal representation of a Kubernetes audit log record.
// Only the fields needed for exec/attach detection are decoded.
type auditEntry struct {
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	SourceIPs []string `json:"sourceIPs"`
	ObjectRef struct {
		Resource  string `json:"resource"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"objectRef"`
	ResponseStatus struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
}

// sensitiveSubresources are API subresources that indicate interactive access
// into a workload.
var sensitiveSubresources = []string{"/exec", "/attach", "/portforward", "/proxy"}

// WatchAuditLog tails a Kubernetes API server audit log file and raises alerts
// for exec/attach/portforward/proxy requests. The file is expected to be in
// JSON format (the default audit policy backend).
//
// It starts reading from the end of the file so historical entries do not
// flood the alert feed. If the file is rotated it reopens it automatically.
func (m *Monitor) WatchAuditLog(ctx context.Context, clusterID, path string) {
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			if err := m.tailAuditFile(ctx, clusterID, path); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[monitor] audit log %s: %v; retrying in %s", path, err, watchReconnectDelay)
				if !sleepCtx(ctx, watchReconnectDelay) {
					return
				}
			}
		}
	}()
}

func (m *Monitor) tailAuditFile(ctx context.Context, clusterID, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Start from the end: only new audit entries produce alerts.
	if _, err := f.Seek(0, 2); err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if scanner.Scan() {
			m.processAuditLine(clusterID, scanner.Bytes())
			continue
		}
		if err := scanner.Err(); err != nil {
			return err
		}

		// No new data: wait briefly, then check for rotation by reopening.
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}

		info, err := f.Stat()
		if err != nil {
			return err
		}
		pos, err := f.Seek(0, 1)
		if err != nil {
			return err
		}
		if pos > info.Size() {
			// File was truncated/rotated: reopen from the start of the new file.
			return fmt.Errorf("audit log rotated")
		}
	}
}

func (m *Monitor) processAuditLine(clusterID string, line []byte) {
	if len(line) == 0 {
		return
	}

	var entry auditEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return
	}
	if entry.Stage != "ResponseComplete" {
		return
	}

	subresource := ""
	for _, s := range sensitiveSubresources {
		if strings.Contains(entry.RequestURI, s) {
			subresource = strings.TrimPrefix(s, "/")
			break
		}
	}
	if subresource == "" {
		return
	}

	if entry.ResponseStatus.Code >= 400 {
		return // failed attempts are still interesting, but keep noise low
	}

	sourceIP := ""
	if len(entry.SourceIPs) > 0 {
		sourceIP = entry.SourceIPs[0]
	}

	target := entry.ObjectRef.Namespace + "/" + entry.ObjectRef.Name
	if target == "/" {
		target = entry.RequestURI
	}

	key := "audit|" + entry.AuditID + "|" + subresource
	if m.markNew(clusterID, key) {
		m.store.AddAlert(models.Alert{
			ID:        m.nextAlertID(),
			ClusterID: clusterID,
			Severity:  "High",
			Message: fmt.Sprintf("[audit] %s session by user %q from %s on %s (%s %s)",
				subresource, entry.User.Username, sourceIP, target, entry.Verb, entry.RequestURI),
			Timestamp: time.Now(),
		})
	}
}
