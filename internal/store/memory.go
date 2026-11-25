package store

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"shortlink/internal/model"
	"shortlink/internal/netutil"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
)

// Query narrows a link listing.
type Query struct {
	CreatorID     string
	Campaign      string
	Status        model.Status
	Host          string // registrable domain of the target
	Domain        string // registrable domain filter for target
	Code          string
	CreatedAfter  time.Time
	CreatedBefore time.Time
	// DueBefore selects links whose NextScanAt <= DueBefore (patrol queue).
	DueBefore time.Time
	Limit     int
	Offset    int
}

// Store is the persistence boundary. The in-memory implementation is what
// ships here; a SQL implementation is a drop-in with the same semantics.
//
// Concurrency contract: every method returns copies, never internal pointers,
// so callers may hold them across goroutines.
type Store interface {
	Create(l *model.Link) error
	Get(id string) (*model.Link, error)
	GetByCode(code string) (*model.Link, error)
	Update(l *model.Link) error
	Delete(id string) error
	List(q Query) ([]*model.Link, int, error)
	// CountByCreatorSince counts links a creator made since t (volume signal).
	CountByCreatorSince(creatorID string, since time.Time) (int, error)
	// CountDistinctDomainsByCampaign counts distinct target registrable
	// domains seen under a campaign.
	CountDistinctDomainsByCampaign(campaign string) (int, error)
}

// Memory is a concurrency-safe in-memory Store.
type Memory struct {
	mu     sync.RWMutex
	byID   map[string]*model.Link
	byCode map[string]*model.Link
	// creatorIndex supports cheap volume counts.
	creatorIndex    map[string][]*model.Link
	campaignDomains map[string]map[string]struct{}
}

func NewMemory() *Memory {
	return &Memory{
		byID:            make(map[string]*model.Link),
		byCode:          make(map[string]*model.Link),
		creatorIndex:    make(map[string][]*model.Link),
		campaignDomains: make(map[string]map[string]struct{}),
	}
}

func (m *Memory) Create(l *model.Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[l.ID]; ok {
		return ErrConflict
	}
	if _, ok := m.byCode[l.Code]; ok {
		return ErrConflict
	}
	c := l.Clone()
	m.byID[l.ID] = c
	m.byCode[l.Code] = c
	m.creatorIndex[l.Creator.ID] = append(m.creatorIndex[l.Creator.ID], c)
	if l.Campaign != "" {
		key := campaignKey(l.Campaign)
		dm := m.campaignDomains[key]
		if dm == nil {
			dm = make(map[string]struct{})
			m.campaignDomains[key] = dm
		}
		if host := registrableOf(l.Target); host != "" {
			dm[host] = struct{}{}
		}
	}
	return nil
}

func (m *Memory) Get(id string) (*model.Link, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return l.Clone(), nil
}

func (m *Memory) GetByCode(code string) (*model.Link, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.byCode[strings.ToLower(code)]
	if !ok {
		return nil, ErrNotFound
	}
	return l.Clone(), nil
}

func (m *Memory) Update(l *model.Link) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.byID[l.ID]
	if !ok {
		return ErrNotFound
	}
	c := l.Clone()
	m.byID[l.ID] = c
	if old.Code != c.Code {
		delete(m.byCode, old.Code)
	}
	m.byCode[c.Code] = c
	// Refresh creator index entry.
	idx := m.creatorIndex[c.Creator.ID]
	for i, x := range idx {
		if x.ID == c.ID {
			idx[i] = c
			break
		}
	}
	return nil
}

func (m *Memory) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	delete(m.byID, id)
	delete(m.byCode, l.Code)
	return nil
}

func (m *Memory) List(q Query) ([]*model.Link, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []*model.Link
	if q.CreatorID != "" {
		all = m.creatorIndex[q.CreatorID]
	} else {
		all = make([]*model.Link, 0, len(m.byID))
		for _, l := range m.byID {
			all = append(all, l)
		}
	}
	var out []*model.Link
	for _, l := range all {
		if q.Campaign != "" && !strings.EqualFold(l.Campaign, q.Campaign) {
			continue
		}
		if q.Status != "" && l.Status != q.Status {
			continue
		}
		if q.Code != "" && !strings.EqualFold(l.Code, q.Code) {
			continue
		}
		if q.Domain != "" && registrableOf(l.Target) != q.Domain {
			continue
		}
		if !q.CreatedAfter.IsZero() && l.CreatedAt.Before(q.CreatedAfter) {
			continue
		}
		if !q.CreatedBefore.IsZero() && l.CreatedAt.After(q.CreatedBefore) {
			continue
		}
		if !q.DueBefore.IsZero() && l.NextScanAt.After(q.DueBefore) {
			continue
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	total := len(out)
	off := q.Offset
	if off > len(out) {
		off = len(out)
	}
	out = out[off:]
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	res := make([]*model.Link, len(out))
	for i, l := range out {
		res[i] = l.Clone()
	}
	return res, total, nil
}

func (m *Memory) CountByCreatorSince(creatorID string, since time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, l := range m.creatorIndex[creatorID] {
		if !l.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) CountDistinctDomainsByCampaign(campaign string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.campaignDomains[campaignKey(campaign)]), nil
}

func campaignKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func registrableOf(raw string) string {
	return netutil.Registrable(netutil.HostOf(raw))
}
