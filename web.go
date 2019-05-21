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
	useragent "github.com/mssola/user_agent"
	geoip2 "github.com/oschwald/geoip2-golang"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/net/publicsuffix"
)

var (
	SessionCookieName    = "__frequency_session"
	SessionCookieNameSSO = "__frequency_sso_session"

	geoLite2Database = "GeoLite2-Country.mmdb"
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
	HTTPHost string
	Info     Info
	SAML     *samlsp.Middleware
	Email    string
	Admin    bool

	// Paging
	Page int

	// Additional
	DaysAgo7  int64
	DaysAgo30 int64
	DaysAgo90 int64

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
			return t.In(getTimezone()).Format(time.UnixDate)
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
			t := time.Unix(n, 0).In(getTimezone())
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
		"ssoprovider": func() string {
			if samlSP == nil {
				return ""
			}
			redirect, err := url.Parse(samlSP.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding))
			if err != nil {
				logger.Warnf("SSO redirect invalid URL: %s", err)
				return "unknown"
			}
			domain, err := publicsuffix.EffectiveTLDPlusOne(redirect.Host)
			if err != nil {
				logger.Warnf("SSO redirect invalid URL domain: %s", err)
				return "unknown"
			}
			suffix, icann := publicsuffix.PublicSuffix(domain)
			if icann {
				suffix = "." + suffix
			}
			return strings.Title(strings.TrimSuffix(domain, suffix))
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
			Time:     time.Now().In(getTimezone()),
			Version:  version,
			Request:  r,
			Section:  section,
			Info:     config.FindInfo(),
			HTTPHost: httpHost,
			SAML:     samlSP,
		}

		var public = map[string]bool{
			"signin":    true,
			"forgot":    true,
			"configure": true,
			"analytics": true,
			"ping":      true,
		}

		// Short-circuit signout requests so we don't create a session
		// while trying to sign out a session.
		if section == "signout" {
			h(web)
			return
		}

		// Send user to custom domain URL if one is configured.
		// Without forcing them, so they can avoid it if there's a DNS issue, etc.
		if domain := config.FindInfo().Domain; domain != "" {
			if r.Host != domain {
				if section == "index" {
					web.Redirect("/domain")
					return
				}
			}
		}

		// Has a valid session.
		if session, _ := ValidateSession(r); session != nil {
			web.Admin = session.Admin
		} else if samlSP != nil {
			// SAML auth.
			if token := samlSP.GetAuthorizationToken(r); token != nil {
				r = r.WithContext(samlsp.WithToken(r.Context(), token))

				email := token.StandardClaims.Subject
				if email == "" {
					Error(w, fmt.Errorf("SAML token missing email"))
					return
				}

				web.Email = email
				web.Admin = true

				logger.Debugf("valid SSO token, signing in session")
				if err := web.SigninSession(true); err != nil {
					Error(web.w, err)
					return
				}
			}
		}

		if web.Admin || public[section] {
			h(web)
			return
		}

		if !config.FindInfo().Configured {
			web.Redirect("/configure")
			return
		}

		logger.Warnf("auth: sign in required")
		web.Redirect("/signin")
	}
}

func Log(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		start := time.Now()
		h(w, r, ps)
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		ua := r.Header.Get("User-Agent")
		xff := r.Header.Get("X-Forwarded-For")
		xrealip := r.Header.Get("X-Real-IP")
		rang := r.Header.Get("Range")

		logger.Infof("%s %q %q %q %q %q %q %s %q %d ms", start, ip, xff, xrealip, ua, rang, r.Referer(), r.Method, r.RequestURI, int64(time.Since(start)/time.Millisecond))
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

func (w *Web) SignoutSession() {
	domain, _, err := net.SplitHostPort(w.r.Host)
	if err != nil {
		logger.Warnf("parsing Host header failed: %s", err)
	}
	http.SetCookie(w.w, &http.Cookie{
		Name:     SessionCookieNameSSO,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !httpInsecure,
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
	http.SetCookie(w.w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !httpInsecure,
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func (w *Web) SigninSession(admin bool) error {
	expires := time.Now().Add(12 * time.Hour)

	encoded, err := securetoken.Encode(SessionCookieName, Session{
		Admin:     admin,
		NotBefore: time.Now(),
		NotAfter:  expires,
	})
	if err != nil {
		return fmt.Errorf("auth: encoding error: %s", err)
	}
	domain, _, err := net.SplitHostPort(w.r.Host)
	if err != nil {
		logger.Warnf("parsing Host header failed: %s", err)
	}
	http.SetCookie(w.w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    encoded,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   !httpInsecure,
		Expires:  expires,
	})
	return nil
}
