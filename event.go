package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mailru/easyjson"
)

var MaxThreadsafeAppend = 4096

//easyjson:json
type Event struct {
	Property     string `json:"property"`
	Host         string `json:"host"`
	Path         string `json:"path"`
	Referrer     string `json:"referrer"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
	ScreenWidth  int    `json:"screen_width"`
	ScreenHeight int    `json:"screen_height"`
	Timezone     int    `json:"timezone"`
	Language     string `json:"language"`
	Timestamp    int64  `json:"timestamp"`
}

func (e Event) String() string {
	return fmt.Sprintf("Property: %s\tHost: %s\tPath: %s\tReferrer: %s\tIP Address: %s\nUser Agent: %s\tScreen Width: %d\tScreen Height: %d\tTimestamp: %d", e.Property, e.Host, e.Path, e.Referrer, e.IPAddress, e.UserAgent, e.ScreenWidth, e.ScreenHeight, e.Timestamp)
}

func (e Event) Time() time.Time {
	return time.Unix(e.Timestamp, 0).Local()
}

func (e *Event) Save() {
	timestamp := time.Unix(e.Timestamp, 0).Local()

	y, m, d := timestamp.Date()
	unix := time.Date(y, m, d, timestamp.Hour(), 0, 0, 0, timestamp.Location()).Unix()

	dirname := filepath.Join(datadir, "event", e.Property, fmt.Sprintf("%d", y), fmt.Sprintf("%02d", m), fmt.Sprintf("%02d", d))
	filename := filepath.Join(dirname, fmt.Sprintf("%d.%s.events", unix, e.Property))

	if err := os.MkdirAll(dirname, 0755); err != nil {
		logger.Error(err)
		return
	}

	b, err := json.Marshal(e)
	if err != nil {
		logger.Error(err)
		return
	}
	b = append(b, []byte("\n")...)

	// TODO: look into this issue further.
	// https://stackoverflow.com/questions/1154446/is-file-append-atomic-in-unix
	if len(b) > MaxThreadsafeAppend {
		logger.Error(fmt.Errorf("event exceeded threadsafe append %d > %d", len(b), MaxThreadsafeAppend))
		return
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error(err)
		return
	}
	if _, err := f.Write(b); err != nil {
		logger.Error(err)
		return
	}
	if err := f.Close(); err != nil {
		logger.Error(err)
		return
	}
}

func eventWalk(propertyID string, start, end int64, fn func(*Event)) {
	files := eventFiles(propertyID, start, end)

	for _, filename := range files {
		f, err := os.Open(filename)
		if err != nil {
			logger.Error(err)
			continue
		}
		compressed := filepath.Ext(filename) == ".gz"

		var scanner *bufio.Scanner
		var fz *gzip.Reader

		if compressed {
			fz, err = gzip.NewReader(f)
			if err != nil {
				logger.Error(err)
				continue
			}
			scanner = bufio.NewScanner(fz)
		} else {
			scanner = bufio.NewScanner(f)
		}

		for scanner.Scan() {
			e := &Event{}
			if err := easyjson.Unmarshal(scanner.Bytes(), e); err != nil {
				logger.Error(err)
				continue
			}
			fn(e)
		}

		if err := scanner.Err(); err != nil {
			logger.Error(err)
		}

		if err := f.Close(); err != nil {
			logger.Error(err)
		}

		if compressed {
			if err := fz.Close(); err != nil {
				logger.Error(err)
			}
		}
	}
}

func eventList(propertyID string, start, end int64, limit, page int) []*Event {
	if limit < 0 || page < 0 {
		return nil
	}

	type nfilevalue struct {
		First int
		Last  int
		Count int
	}

	files := eventFiles(propertyID, start, end)
	nfile := make(map[string]*nfilevalue)

	total := 0
	for _, filename := range files {
		count, err := lines(filename)
		if err != nil {
			logger.Error(err)
			continue
		}
		if count == 0 {
			continue
		}
		first := total + 1
		last := total + count
		nfile[filename] = &nfilevalue{first, last, count}
		total += count
	}

	pagelimit := limit * page

	wantFirst := (total - pagelimit) + 1
	if wantFirst < 0 {
		wantFirst = 0
	}

	wantLast := (total - pagelimit) + limit
	if wantLast < 0 {
		return nil
	}

	seen := 0

	var events []*Event
	for _, filename := range files {
		nfv, ok := nfile[filename]
		if !ok {
			continue
		}

		if nfv.Last < wantFirst {
			seen += nfv.Count
			continue
		}
		compressed := filepath.Ext(filename) == ".gz"

		f, err := os.Open(filename)
		if err != nil {
			logger.Error(err)
			continue
		}

		var scanner *bufio.Scanner
		var fz *gzip.Reader

		if compressed {
			fz, err = gzip.NewReader(f)
			if err != nil {
				logger.Error(err)
				continue
			}
			scanner = bufio.NewScanner(fz)
		} else {
			scanner = bufio.NewScanner(f)
		}

		for scanner.Scan() {
			seen += 1

			if seen < wantFirst {
				continue
			}
			if seen > wantLast {
				continue
			}

			e := &Event{}
			if err := easyjson.Unmarshal(scanner.Bytes(), e); err != nil {
				logger.Error(err)
				continue
			}
			cp := *e
			events = append(events, &cp)
		}

		if err := scanner.Err(); err != nil {
			logger.Error(err)
		}

		if err := f.Close(); err != nil {
			logger.Error(err)
		}

		if compressed {
			if err := fz.Close(); err != nil {
				logger.Error(err)
			}
		}
	}
	return events
}

func eventFiles(propertyID string, start, end int64) []string {
	type eventFileEntry struct {
		Path      string
		Timestamp int64
	}

	now := time.Now().In(getTimezone())

	sy, sm, sd := time.Unix(start, 0).Local().Date()
	ey, em, ed := time.Unix(end, 0).Local().Date()

	startDate := time.Date(sy, sm, sd, 0, 0, 0, 0, now.Location())
	endDate := time.Date(ey, em, ed, 0, 0, 0, 0, now.Location())

	dirname := filepath.Join(datadir, "event", propertyID)

	var entries []*eventFileEntry
	if err := filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Debug(err)
			return nil
		}

		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".events") && !strings.HasSuffix(path, ".events.gz") {
			return nil
		}
		parts := strings.Split(info.Name(), ".")
		if len(parts) == 0 {
			return nil
		}
		timestamp, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil
		}
		tsy, tsm, tsd := time.Unix(timestamp, 0).Local().Date()
		tsDate := time.Date(tsy, tsm, tsd, 0, 0, 0, 0, now.Location())

		if tsDate.Before(startDate) || tsDate.After(endDate) {
			return nil
		}

		entries = append(entries, &eventFileEntry{path, timestamp})
		return nil
	}); err != nil {
		logger.Error(err)
		return nil
	}

	// oldest to newest
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})

	var files []string
	for _, entry := range entries {
		files = append(files, entry.Path)
	}
	return files
}

func eventFilesOld(propertyID string, start, end int64) []string {
	now := time.Now().In(getTimezone())

	sy, sm, sd := time.Unix(start, 0).Local().Date()
	ey, em, ed := time.Unix(end, 0).Local().Date()

	endDate := time.Date(ey, em, ed, 0, 0, 0, 0, now.Location())
	currentDate := time.Date(sy, sm, sd, 0, 0, 0, 0, now.Location())

	var dirs []string
	for {
		if currentDate.After(endDate) {
			break
		}
		y, m, d := currentDate.Date()
		dirname := filepath.Join(datadir, "event", propertyID, fmt.Sprintf("%d", y), fmt.Sprintf("%02d", m), fmt.Sprintf("%02d", d))
		dirs = append(dirs, dirname)
		currentDate = currentDate.AddDate(0, 0, 1)
	}

	var files []string
	for _, dirname := range dirs {
		err := filepath.Walk(dirname, func(path string, _ os.FileInfo, err error) error {
			if !strings.HasSuffix(path, ".events") && !strings.HasSuffix(path, ".events.gz") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			logger.Error(err)
			continue
		}
	}
	sort.Strings(files) // oldest to newest
	return files
}

func eventPurge(propertyID string) error {
	if propertyID == "" {
		return fmt.Errorf("missing property ID")
	}
	dirname := filepath.Join(datadir, "event", propertyID)
	return os.RemoveAll(dirname)
}

func eventPropertyIDs() []string {
	ids := []string{}
	files, err := ioutil.ReadDir(filepath.Join(datadir, "event"))
	if err != nil {
		return ids
	}
	for _, file := range files {
		ids = append(ids, file.Name())
	}
	return ids
}
