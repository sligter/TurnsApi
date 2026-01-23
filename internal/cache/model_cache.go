package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ModelCache provides an in-memory cache for model lists with TTL support
type ModelCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	ttl     time.Duration
}

// CacheEntry represents a cached item with expiration
type CacheEntry struct {
	Data      interface{}
	ExpiresAt time.Time
}

// NewModelCache creates a new model cache with the specified TTL
func NewModelCache(ttl time.Duration) *ModelCache {
	cache := &ModelCache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go cache.cleanupExpired()

	return cache
}

// Get retrieves a value from the cache
// Returns the cached data and true if found and not expired, nil and false otherwise
func (c *ModelCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.Data, true
}

// Set stores a value in the cache with TTL
func (c *ModelCache) Set(key string, data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &CacheEntry{
		Data:      data,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

// Invalidate removes a specific key from the cache
func (c *ModelCache) Invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, key)
}

// Clear removes all entries from the cache
func (c *ModelCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
}

// Size returns the number of entries in the cache
func (c *ModelCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// cleanupExpired periodically removes expired entries
func (c *ModelCache) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// GenerateCacheKey creates a cache key from provider configuration
// Format: {provider_type}:{base_url}:{api_key_hash}
func GenerateCacheKey(providerType, baseURL, apiKey string) string {
	// Hash the API key for security
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:8]) // Use first 8 bytes for brevity

	return providerType + ":" + baseURL + ":" + keyHash
}
