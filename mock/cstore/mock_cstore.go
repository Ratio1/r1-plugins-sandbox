package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Ratio1/r1-plugins-sandbox/internal/devseed"
)

type entry struct {
	data []byte
}

// Mock implements an in-memory CStore replacement backed by simple maps.
type Mock struct {
	mu     sync.RWMutex
	items  map[string]*entry
	hashes map[string]map[string]*entry
}

// New creates an empty mock store.
func New() *Mock {
	return &Mock{
		items:  make(map[string]*entry),
		hashes: make(map[string]map[string]*entry),
	}
}

// Seed loads initial items from seed entries (typically decoded via devseed.LoadCStoreSeed).
func (m *Mock) Seed(entries []devseed.CStoreSeedEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, e := range entries {
		if strings.TrimSpace(e.Key) == "" {
			return fmt.Errorf("mock cstore: seed entry missing key")
		}
		data := append([]byte(nil), e.Value...)
		if len(data) == 0 {
			data = []byte("null")
		}
		m.items[e.Key] = &entry{data: data}
	}
	return nil
}

// Get retrieves a value decoded into T.
func Get[T any](ctx context.Context, store *Mock, key string) (item *Item[T], err error) {
	return getItem[T](ctx, store, key)
}

// Set writes a value.
func Set[T any](ctx context.Context, store *Mock, key string, value T, opts *SetOptions) error {
	return setItem(ctx, store, key, value, opts)
}

// GetStatus reports the in-memory keys currently stored.
func GetStatus(ctx context.Context, store *Mock) (status *Status, err error) {
	if store == nil {
		return nil, fmt.Errorf("mock cstore: store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	store.mu.RLock()
	defer store.mu.RUnlock()

	keys := make([]string, 0, len(store.items))
	for key := range store.items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return &Status{Keys: keys}, nil
}

// HGet retrieves a hash field decoded into T.
func HGet[T any](ctx context.Context, store *Mock, hashKey, field string) (item *HashItem[T], err error) {
	return getHashItem[T](ctx, store, hashKey, field)
}

// HSet writes a hash field.
func HSet[T any](ctx context.Context, store *Mock, hashKey, field string, value T, opts *SetOptions) error {
	return setHashItem(ctx, store, hashKey, field, value, opts)
}

// HGetAll retrieves all hash fields for a hash key.
func HGetAll[T any](ctx context.Context, store *Mock, hashKey string) (items []HashItem[T], err error) {
	return listHashItems[T](ctx, store, hashKey)
}

func getItem[T any](ctx context.Context, store *Mock, key string) (*Item[T], error) {
	if strings.TrimSpace(key) == "" {
		return nil, fmt.Errorf("mock cstore: key is required")
	}
	if store == nil {
		return nil, fmt.Errorf("mock cstore: store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	store.mu.RLock()
	ent, ok := store.items[key]
	store.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	var value T
	if err := json.Unmarshal(ent.data, &value); err != nil {
		return nil, fmt.Errorf("mock cstore: decode value: %w", err)
	}

	return &Item[T]{
		Key:   key,
		Value: value,
	}, nil
}

func setItem[T any](ctx context.Context, store *Mock, key string, value T, opts *SetOptions) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("mock cstore: key is required")
	}
	if store == nil {
		return fmt.Errorf("mock cstore: store is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("mock cstore: encode value: %w", err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	store.items[key] = &entry{data: append([]byte(nil), payload...)}
	return nil
}

func getHashItem[T any](ctx context.Context, store *Mock, hashKey, field string) (*HashItem[T], error) {
	if strings.TrimSpace(hashKey) == "" {
		return nil, fmt.Errorf("mock cstore: hash key is required")
	}
	if strings.TrimSpace(field) == "" {
		return nil, fmt.Errorf("mock cstore: hash field is required")
	}
	if store == nil {
		return nil, fmt.Errorf("mock cstore: store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	store.mu.RLock()
	bucket := store.hashes[hashKey]
	ent, ok := bucket[field]
	store.mu.RUnlock()
	if !ok {
		return nil, nil
	}

	var value T
	if err := json.Unmarshal(ent.data, &value); err != nil {
		return nil, fmt.Errorf("mock cstore: decode hash field: %w", err)
	}

	return &HashItem[T]{
		HashKey: hashKey,
		Field:   field,
		Value:   value,
	}, nil
}

func setHashItem[T any](ctx context.Context, store *Mock, hashKey, field string, value T, opts *SetOptions) error {
	if strings.TrimSpace(hashKey) == "" {
		return fmt.Errorf("mock cstore: hash key is required")
	}
	if strings.TrimSpace(field) == "" {
		return fmt.Errorf("mock cstore: hash field is required")
	}
	if store == nil {
		return fmt.Errorf("mock cstore: store is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("mock cstore: encode hash value: %w", err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	bucket := store.hashes[hashKey]
	if bucket == nil {
		bucket = make(map[string]*entry)
		store.hashes[hashKey] = bucket
	}
	bucket[field] = &entry{data: append([]byte(nil), payload...)}
	return nil
}

func listHashItems[T any](ctx context.Context, store *Mock, hashKey string) ([]HashItem[T], error) {
	if strings.TrimSpace(hashKey) == "" {
		return nil, fmt.Errorf("mock cstore: hash key is required")
	}
	if store == nil {
		return nil, fmt.Errorf("mock cstore: store is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	store.mu.RLock()
	bucket := store.hashes[hashKey]
	store.mu.RUnlock()
	if len(bucket) == 0 {
		return nil, nil
	}

	fields := make([]string, 0, len(bucket))
	for field := range bucket {
		fields = append(fields, field)
	}
	sort.Strings(fields)

	items := make([]HashItem[T], 0, len(fields))
	for _, field := range fields {
		ent := bucket[field]
		var value T
		if err := json.Unmarshal(ent.data, &value); err != nil {
			return nil, fmt.Errorf("mock cstore: decode hash field %s: %w", field, err)
		}
		items = append(items, HashItem[T]{HashKey: hashKey, Field: field, Value: value})
	}
	return items, nil
}
