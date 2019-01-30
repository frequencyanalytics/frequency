package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"
	httprouter "github.com/julienschmidt/httprouter"
	useragent "github.com/mssola/user_agent"
	geoip2 "github.com/oschwald/geoip2-golang"
)

var (
	SessionCookieName = "__frequency_session"
	geoLite2Database  = "GeoLite2-Country.mmdb"
)

type Session struct {
	Admin     bool
	NotBefore time.Time
	NotAfter  time.Time
}

type Web struct {
	// Internal
	w        http.ResponseWriter
	r        *http.Request
	ps       httprouter.Params
	template string

	// Default
	Backlink string
	Version  string
	Request  *http.Request
	Section  string
	Time     time.Time
	Info     Info

	// Paging
	Page int

	// Additional
	Property   Property
	Properties []Property

	Start int64
	End   int64

	Stats Stats
}

func init() {
	gob.Register(Session{})
}

func Error(w http.ResponseWriter, err error) {
	logger.Error(err)

	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, errorPageHTML+"\n")
}

func (w *Web) HTML() {
	t := template.New(w.template).Funcs(template.FuncMap{
		"url2host": func(rawurl string) string {
			if rawurl == "" {
				return ""
			}
			u, err := url.Parse(rawurl)
			if err != nil {
				logger.Warn(err)
				return ""
			}
			return strings.TrimPrefix(u.Host, "www.")
		},
		"hasprefix": strings.HasPrefix,
		"hassuffix": strings.HasSuffix,
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"bytes": func(n int64) string {
			return fmt.Sprintf("%.2f GB", float64(n)/1024/1024/1024)
		},
		"date": func(t time.Time) string {
			return t.Format(time.UnixDate)
		},
		"time": humanize.Time,
		"jsfloat64": func(n float64) template.JS {
			return template.JS(fmt.Sprintf("%.0f", n))
		},
		"jsint": func(n int) template.JS {
			return template.JS(fmt.Sprintf("%d", n))
		},
		"jsint64": func(n int) template.JS {
			return template.JS(fmt.Sprintf("%d", n))
		},
		"truncate": func(s string, n int) string {
			if len(s) > n {
				s = s[:n-3] + "..."
			}
			return s
		},
		"timestamp": func(n int64) string {
			t := time.Unix(n, 0).Local()
			return t.Format("2006/01/02")
		},
		"ip2country": func(ipAddress string) string {
			if ipAddress == "" {
				return ""
			}
			db, err := geoip2.Open(filepath.Join(datadir, geoLite2Database))
			if err != nil {
				logger.Warn(err)
				return ""
			}
			defer db.Close()
			ip := net.ParseIP(ipAddress)
			record, err := db.Country(ip)
			if err != nil {
				logger.Warn(err)
				return ""
			}
			return strings.ToLower(record.Country.IsoCode)
		},
		"useragent": func(userAgent string) string {
			ua := useragent.New(userAgent)
			name, _ := ua.Browser()
			return normalizeBrowserName(name, ua.OS())
		},
	})

	for _, filename := range AssetNames() {
		if !strings.HasPrefix(filename, "templates/") {
			continue
		}
		name := strings.TrimPrefix(filename, "templates/")
		b, err := Asset(filename)
		if err != nil {
			Error(w.w, err)
			return
		}

		var tmpl *template.Template
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		if _, err := tmpl.Parse(string(b)); err != nil {
			Error(w.w, err)
			return
		}
	}

	w.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w.w, w); err != nil {
		Error(w.w, err)
		return
	}
}

func (w *Web) Redirect(format string, a ...interface{}) {
	location := fmt.Sprintf(format, a...)
	http.Redirect(w.w, w.r, location, http.StatusFound)
}

func WebHandler(h func(*Web), section string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		web := &Web{
			w:        w,
			r:        r,
			ps:       ps,
			template: section + ".html",

			Backlink: backlink,
			Time:     time.Now(),
			Version:  version,
			Request:  r,
			Section:  section,
			Info:     config.FindInfo(),
		}

		var public = map[string]bool{
			"signin":    true,
			"forgot":    true,
			"configure": true,
			"analytics": true,
			"ping":      true,
		}

		if public[section] {
			h(web)
			return
		}

		if !config.FindInfo().Configured {
			web.Redirect("/configure")
			return
		}

		session, _ := ValidateSession(r)
		if session == nil || !session.Admin {
			logger.Errorf("auth failed")
			web.Redirect("/signin")
			return
		}
		h(web)
	}
}

func Log(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		start := time.Now()
		h(w, r, ps)
		rang := r.Header.Get("Range")
		logger.Infof("%d %q %s %q %d ms", start.Unix(), rang, r.Method, r.RequestURI, int64(time.Since(start)/time.Millisecond))
	}
}

func Auth(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	}
}

func staticHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	serveAsset(w, r, ps.ByName("path"))
}

func serveAsset(w http.ResponseWriter, r *http.Request, filename string) {
	path := "static" + filename

	b, err := Asset(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fi, err := AssetInfo(path)
	if err != nil {
		Error(w, err)
		return
	}
	http.ServeContent(w, r, path, fi.ModTime(), bytes.NewReader(b))
}

func ValidateSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, fmt.Errorf("auth: missing cookie")
	}
	session := &Session{}
	if err := securetoken.Decode(SessionCookieName, cookie.Value, session); err != nil {
		return nil, err
	}
	if time.Now().Before(session.NotBefore) {
		return nil, fmt.Errorf("invalid session (before valid)")
	}
	if time.Now().After(session.NotAfter) {
		return nil, fmt.Errorf("invalid session (expired session.NotAfter is %s and now is %s)", session.NotAfter, time.Now())
	}
	return session, nil
}

func NewDeletionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	}
}

func NewSessionCookie(r *http.Request) (*http.Cookie, error) {
	expires := time.Now().Add(720 * time.Hour)

	session := Session{
		Admin:     true,
		NotBefore: time.Now(),
		NotAfter:  expires,
	}

	encoded, err := securetoken.Encode(SessionCookieName, session)
	if err != nil {
		return nil, fmt.Errorf("auth: encoding error: %s", err)
	}

	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  expires,
	}
	return cookie, nil
}
