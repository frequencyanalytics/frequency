package main

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	useragent "github.com/mssola/user_agent"
)

var (
	seDomains = []string{
		"google",
		"bing",
		"yahoo",
		"ask.com",
		"aol.com",
		"duckduckgo.com",
		"duck.com",
	}
	snsDomains = []string{
		"reddit.com",
		"news.ycombinator.com",
		"facebook.com",
		"twitter.com",
		"instagram.com",
		"snapchat.com",
		"pinterest.com",
		"tumblr.com",
	}
)

type Stats struct {
	Sources       StatSources
	Pages         StatPages
	PagesChart    StatPagesChart
	VisitorsChart StatVisitorsChart
	Referrers     StatReferrers
	Platforms     StatPlatforms
	Events        StatEvents
}

type Stat struct {
	Property string
	Start    int64
	End      int64
}

func NewStat(property string, start, end int64) *Stat {
	now := time.Now()

	sy, sm, sd := time.Unix(start, 0).Date()
	ey, em, ed := time.Unix(end, 0).Date()

	start = time.Date(sy, sm, sd, 0, 0, 0, 0, now.Location()).Unix()
	end = time.Date(ey, em, ed, 0, 0, 0, 0, now.Location()).Unix()

	return &Stat{
		Property: property,
		Start:    start,
		End:      end,
	}
}

//
// StatPages
//

type StatPagesEntry struct {
	Path string
	Hits int
}

type StatPages []*StatPagesEntry

func (pages StatPages) Len() int      { return len(pages) }
func (pages StatPages) Swap(i, j int) { pages[i], pages[j] = pages[j], pages[i] }
func (pages StatPages) Less(i, j int) bool {
	if pages[i].Hits == pages[j].Hits {
		return pages[i].Path > pages[j].Path
	}
	return pages[i].Hits > pages[j].Hits
}

func (s *Stat) Pages(n int) StatPages {
	pagehit := make(map[string]int)

	eventWalk(s.Property, s.Start, s.End, func(e *Event) {
		pagehit[e.Path] += 1
	})

	var pages StatPages

	for path, hits := range pagehit {
		pages = append(pages, &StatPagesEntry{path, hits})
	}

	sort.Sort(pages)
	if len(pages) > n {
		pages = pages[:n]
	}
	return pages
}

//
// StatSources
//

type StatSources struct {
	Direct float64
	Search float64
	Social float64
	Other  float64
}

func (s *Stat) Sources() StatSources {
	var direct, search, social, other int

	eventWalk(s.Property, s.Start, s.End, func(e *Event) {
		// Direct
		if e.Referrer == "" {
			direct += 1
			return
		}

		referrer, err := url.Parse(e.Referrer)
		if err != nil {
			return
		}
		host := referrer.Host

		// Don't count ourselves as a referrer
		if e.Host == host {
			return
		}

		// Search
		for _, se := range seDomains {
			if strings.Contains(host, se) {
				search += 1
				return
			}
		}

		// Social
		for _, sns := range snsDomains {
			if strings.Contains(host, sns) {
				social += 1
				return
			}
		}

		// Other
		other += 1
	})

	total := direct + search + social + other

	return StatSources{
		Direct: (float64(direct) / float64(total)) * 100,
		Search: (float64(search) / float64(total)) * 100,
		Social: (float64(social) / float64(total)) * 100,
		Other:  (float64(other) / float64(total)) * 100,
	}
}

//
// StatReferrers
//
type StatReferrersEntry struct {
	Domain string
	Hits   int
}

type StatReferrers []*StatReferrersEntry

func (r StatReferrers) Len() int      { return len(r) }
func (r StatReferrers) Swap(i, j int) { r[i], r[j] = r[j], r[i] }
func (r StatReferrers) Less(i, j int) bool {
	if r[i].Hits == r[j].Hits {
		return r[i].Domain > r[j].Domain
	}
	return r[i].Hits > r[j].Hits
}

func (s *Stat) Referrers(n int) StatReferrers {
	domainhit := make(map[string]int)

	eventWalk(s.Property, s.Start, s.End, func(e *Event) {
		referrer, err := url.Parse(e.Referrer)
		if err != nil {
			return
		}
		host := strings.TrimPrefix(referrer.Host, "www.")
		if host == "" {
			return
		}
		if host == strings.TrimPrefix(e.Host, "www.") {
			return
		}
		domainhit[host] += 1
	})

	var r StatReferrers

	for domain, hits := range domainhit {
		r = append(r, &StatReferrersEntry{domain, hits})
	}
	sort.Sort(r)
	if len(r) > n {
		r = r[:n]
	}
	return r
}

//
// StatPlatforms
//
type StatPlatformsEntry struct {
	Name string
	Hits int
}

type StatPlatforms []*StatPlatformsEntry

func (p StatPlatforms) Len() int      { return len(p) }
func (p StatPlatforms) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p StatPlatforms) Less(i, j int) bool {
	if p[i].Hits == p[j].Hits {
		return p[i].Name > p[j].Name
	}
	return p[i].Hits > p[j].Hits
}

func (s *Stat) Platforms(n int) StatPlatforms {
	browserhit := make(map[string]int)

	eventWalk(s.Property, s.Start, s.End, func(e *Event) {
		ua := useragent.New(e.UserAgent)
		name, _ := ua.Browser()
		name = normalizeBrowserName(name, ua.OS())
		browserhit[name] += 1
	})

	var p StatPlatforms

	for name, hits := range browserhit {
		p = append(p, &StatPlatformsEntry{name, hits})
	}
	sort.Sort(p)
	if len(p) > n {
		p = p[:n]
	}
	return p
}

//
// StatPagesChart
//

type StatPagesChartEntry struct {
	Time time.Time
	Hits int
}

type StatPagesChart []*StatPagesChartEntry

func (p StatPagesChart) Len() int      { return len(p) }
func (p StatPagesChart) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p StatPagesChart) Less(i, j int) bool {
	return p[i].Time.After(p[j].Time)
}

func (s *Stat) PagesChart(path string) StatPagesChart {
	th := make(map[int64]int)

	eventWalk(s.Property, s.Start, s.End, func(e *Event) {
		if path != "" {
			if e.Path != path {
				return
			}
		}
		ts := time.Unix(e.Timestamp, 0)
		y, m, d := ts.Date()
		key := time.Date(y, m, d, ts.Hour(), 0, 0, 0, ts.Location()).Unix()
		th[key] += 1
	})

	var pages StatPagesChart
	for t, hits := range th {
		pages = append(pages, &StatPagesChartEntry{time.Unix(t, 0), hits})
	}
	sort.Sort(pages)
	return pages
}

//
// StatEvents
//
type StatEvents []*Event

func (e StatEvents) Len() int      { return len(e) }
func (e StatEvents) Swap(i, j int) { e[i], e[j] = e[j], e[i] }
func (e StatEvents) Less(i, j int) bool {
	if e[i].Timestamp == e[j].Timestamp {
		return e[i].UserAgent < e[j].UserAgent
	}
	return e[i].Timestamp > e[j].Timestamp
}

func (s *Stat) Events(limit, page int) StatEvents {
	var events StatEvents
	for _, e := range eventList(s.Property, s.Start, s.End, limit, page) {
		events = append(events, e)
	}
	sort.Sort(events)
	return events
}

//
// StatVisitorsChart
//

type StatVisitorsChartEntry struct {
	Time  time.Time
	Count int
}

type StatVisitorsChart []*StatVisitorsChartEntry

func (v StatVisitorsChart) Len() int      { return len(v) }
func (v StatVisitorsChart) Swap(i, j int) { v[i], v[j] = v[j], v[i] }
func (v StatVisitorsChart) Less(i, j int) bool {
	return v[i].Time.After(v[j].Time)
}

func (s *Stat) VisitorsChart() StatVisitorsChart {
	tc := make(map[int64]map[string]int)

	eventWalk(s.Property, s.Start, s.End, func(e *Event) {
		if e.UserAgent == "" {
			return
		}
		if e.IPAddress == "" {
			return
		}

		ts := time.Unix(e.Timestamp, 0)
		y, m, d := ts.Date()
		tkey := time.Date(y, m, d, 0, 0, 0, 0, ts.Location()).Unix()
		if _, ok := tc[tkey]; !ok {
			tc[tkey] = make(map[string]int)
		}
		vkey := fmt.Sprintf("%s/%s", e.UserAgent, e.IPAddress)
		tc[tkey][vkey] = 1
	})

	var visitors StatVisitorsChart
	for t, v := range tc {
		visitors = append(visitors, &StatVisitorsChartEntry{time.Unix(t, 0), len(v)})
	}
	sort.Sort(visitors)
	return visitors
}
