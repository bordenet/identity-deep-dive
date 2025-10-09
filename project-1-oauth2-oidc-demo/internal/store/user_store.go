package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bordenet/identity-deep-dive/project-1-oauth2-oidc-demo/pkg/models"
)

// InMemoryUserStore is a simple in-memory user store for demo purposes
// In production, this would be backed by a real database
type InMemoryUserStore struct {
	users map[string]*models.User
	mu    sync.RWMutex
}

// NewInMemoryUserStore creates a new in-memory user store with demo users
func NewInMemoryUserStore() *InMemoryUserStore {
	store := &InMemoryUserStore{
		users: make(map[string]*models.User),
	}

	// Add demo users
	store.addDemoUsers()

	return store
}

// GetUser retrieves a user by ID
func (s *InMemoryUserStore) GetUser(ctx context.Context, userID string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[userID]
	if !ok {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	return user, nil
}

// CreateUser creates a new user
func (s *InMemoryUserStore) CreateUser(ctx context.Context, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("user already exists: %s", user.ID)
	}

	user.CreatedAt = time.Now()
	s.users[user.ID] = user

	return nil
}

// addDemoUsers adds some demo users for testing
func (s *InMemoryUserStore) addDemoUsers() {
	demoUsers := []*models.User{
		{
			ID:            "demo-user-123",
			Email:         "alice@example.com",
			EmailVerified: true,
			Name:          "Alice Demo",
			GivenName:     "Alice",
			FamilyName:    "Demo",
			Picture:       "https://i.pravatar.cc/150?img=1",
			Profile:       "https://example.com/alice",
			CreatedAt:     time.Now(),
		},
		{
			ID:            "user-456",
			Email:         "bob@example.com",
			EmailVerified: true,
			Name:          "Bob Smith",
			GivenName:     "Bob",
			FamilyName:    "Smith",
			Picture:       "https://i.pravatar.cc/150?img=2",
			Profile:       "https://example.com/bob",
			CreatedAt:     time.Now(),
		},
		{
			ID:            "user-789",
			Email:         "charlie@example.com",
			EmailVerified: false,
			Name:          "Charlie Johnson",
			GivenName:     "Charlie",
			FamilyName:    "Johnson",
			Picture:       "https://i.pravatar.cc/150?img=3",
			Profile:       "https://example.com/charlie",
			CreatedAt:     time.Now(),
		},
	}

	for _, user := range demoUsers {
		s.users[user.ID] = user
	}
}
