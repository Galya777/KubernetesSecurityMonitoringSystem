package storage

import (
	"testing"
	"time"

	"KubernetesSecurityMonitoringSystem/internal/models"
)

func TestMemoryStorageUserLifecycle(t *testing.T) {
	s := NewMemoryStorage()
	u := models.User{ID: "u1", Email: "a@b.c", Password: "hash", Role: models.RoleStudent, CreatedAt: time.Now()}

	if err := s.AddUser(u); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := s.AddUser(u); err == nil {
		t.Fatal("expected duplicate user error")
	}

	got, err := s.GetUserByEmail("a@b.c")
	if err != nil || got.ID != "u1" {
		t.Fatalf("GetUserByEmail: %v %+v", err, got)
	}

	u.FirstName = "New"
	if err := s.UpdateUser(u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, _ = s.GetUser("u1")
	if got.FirstName != "New" {
		t.Fatalf("update not persisted: %+v", got)
	}

	if err := s.DeleteUser("u1"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := s.GetUser("u1"); err == nil {
		t.Fatal("expected user not found after delete")
	}
}

func TestMemoryStorageAlertsAreCopiedAndCapped(t *testing.T) {
	s := NewMemoryStorage()
	for i := 0; i < maxAlerts+50; i++ {
		s.AddAlert(models.Alert{ID: "a", Message: "m", Timestamp: time.Now()})
	}
	alerts := s.GetAlerts()
	if len(alerts) != maxAlerts {
		t.Fatalf("expected %d alerts after cap, got %d", maxAlerts, len(alerts))
	}
	// Mutating the returned slice must not affect storage.
	alerts[0].Message = "tampered"
	if s.GetAlerts()[0].Message == "tampered" {
		t.Fatal("GetAlerts returned internal slice")
	}
}

func TestMemoryStorageContainerAttach(t *testing.T) {
	s := NewMemoryStorage()
	_ = s.AddUser(models.User{ID: "u1", Email: "x@y.z", CreatedAt: time.Now()})
	_ = s.AddContainer(models.Container{ID: "c1", ClusterID: "cl", Namespace: "default", PodName: "p", ContainerName: "app"})

	if err := s.AttachContainerToUser("u1", "c1"); err != nil {
		t.Fatalf("AttachContainerToUser: %v", err)
	}
	containers, err := s.GetContainersByUser("u1")
	if err != nil || len(containers) != 1 {
		t.Fatalf("GetContainersByUser: %v %v", err, containers)
	}
	if err := s.DetachContainerFromUser("u1", "c1"); err != nil {
		t.Fatalf("DetachContainerFromUser: %v", err)
	}
	containers, _ = s.GetContainersByUser("u1")
	if len(containers) != 0 {
		t.Fatalf("expected 0 containers after detach, got %d", len(containers))
	}
}
