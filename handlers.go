package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/publicsuffix"
	//chart "github.com/wcharczuk/go-chart"
	useragent "github.com/mssola/user_agent"
)

var (
	validEmail    = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString   = regexp.MustCompile(`^[ -~]{1,200}$`)

	// Base64
	transparentPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=="
)

func pingHandler(w *Web) {
	property := w.r.FormValue("property")
	path := w.r.FormValue("path")
	host := w.r.FormValue("host")
	referrer := w.r.FormValue("referrer")

	ipAddress, _, _ := net.SplitHostPort(w.r.RemoteAddr)
	if octets := strings.Split(ipAddress, "."); len(octets) == 4 {
		ipAddress = fmt.Sprintf("%s.%s.%s.0", octets[0], octets[1], octets[2])
	}

	userAgent := w.r.Header.Get("User-Agent")
	screenWidth, _ := strconv.Atoi(w.r.FormValue("width"))
	screenHeight, _ := strconv.Atoi(w.r.FormValue("height"))
	timezone, _ := strconv.Atoi(w.r.FormValue("timezone"))
	language := w.r.FormValue("language")
	timestamp := time.Now().Unix()

	// Save events from non-bots.
	if !useragent.New(userAgent).Bot() {
		event := &Event{
			Property:     property,
			Host:         host,
			Path:         path,
			Referrer:     referrer,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			ScreenWidth:  screenWidth,
			ScreenHeight: screenHeight,
			Timezone:     timezone,
			Language:     language,
			Timestamp:    timestamp,
		}
		go event.Save()
	}

	png, err := base64.StdEncoding.DecodeString(transparentPNG)
	if err != nil {
		logger.Error(err)
		return
	}
	if _, err := w.w.Write(png); err != nil {
		logger.Error(err)
		return
	}
}

func configureHandler(w *Web) {
	if config.FindInfo().Configured {
		w.Redirect("/?error=configured")
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	emailConfirm := strings.ToLower(strings.TrimSpace(w.r.FormValue("email_confirm")))
	password := w.r.FormValue("password")

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
		w.Redirect("/configure?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Password = hashedPassword
		i.Configured = true
		return nil
	})

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	w.Redirect("/")
	return
}

func forgotHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	secret := w.r.FormValue("secret")
	password := w.r.FormValue("password")

	if email != "" && !validEmail.MatchString(email) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if secret != "" && !validString.MatchString(secret) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if email != "" && secret != "" && !validPassword.MatchString(password) {
		w.Redirect("/forgot?error=invalid&email=%s&secret=%s", email, secret)
		return
	}

	if email != config.FindInfo().Email {
		w.Redirect("/forgot?error=invalid")
		return
	}

	if secret == "" {
		secret = config.FindInfo().Secret
		if secret == "" {
			secret = randomString(32)
			config.UpdateInfo(func(i *Info) error {
				if i.Secret == "" {
					i.Secret = secret
				}
				return nil
			})
		}

		go func() {
			if err := mailer.Forgot(email, secret); err != nil {
				logger.Error(err)
			}
		}()

		w.Redirect("/forgot?success=forgot")
		return
	}

	if secret != config.FindInfo().Secret {
		w.Redirect("/forgot?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Password = hashedPassword
		i.Secret = ""
		return nil
	})

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	w.Redirect("/")
	return
}

func signoutHandler(w *Web) {
	http.SetCookie(w.w, NewDeletionCookie())
	w.Redirect("/signin")
}

func signinHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	if email != config.FindInfo().Email {
		w.Redirect("/signin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(password)); err != nil {
		w.Redirect("/signin?error=invalid")
		return
	}
	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)

	w.Redirect("/")
}
func indexHandler(w *Web) {
	w.Properties = config.ListProperties()
	w.HTML()
}

func analyticsHandler(w *Web) {
	script := fmt.Sprintf(`
(function() {
    if (window.fa.initialized) {
        return;
    }
    var queue = window.fa.queue.slice();
    var property = '';

    window.fa = function() {
        var command = arguments[0];

        if (command === 'create') {
            property = arguments[1];
        } else if (command === 'send') {
            if (arguments[1] === 'pageview') {
                var ping = document.createElement('img');
                ping.src = 'https://%s/ping?property='+encodeURIComponent(property)+'&host='+encodeURIComponent(document.location.hostname)+'&path='+encodeURIComponent(window.location.pathname)+'&width='+window.screen.availWidth+'&height='+window.screen.availHeight+'&referrer='+encodeURIComponent(document.referrer)+'&timezone='+encodeURIComponent(new Date().getTimezoneOffset())+'&language='+encodeURIComponent(window.navigator.language);
                ping.width = 1;
                ping.height = 1;

                var script = document.scripts[document.scripts.length - 1];
                script.parentElement.insertBefore(ping, script);
            }
        }
    }
    window.fa.initialized = true;

    for (var i = 0; i < queue.length; i++) {
        fa.apply(null, queue[i]);
    }
})()
`, w.r.Host)

	w.w.Header().Set("Content-Type", "text/javascript")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", len(script)))
	w.w.Write([]byte(script))
}

func settingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")
	domain := strings.TrimSpace(w.r.FormValue("domain"))

	if currentPassword != "" || newPassword != "" {
		if !validPassword.MatchString(newPassword) {
			w.Redirect("/settings?error=invalid")
			return
		}

		if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(currentPassword)); err != nil {
			w.Redirect("/settings?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/settings?error=bcrypt")
			return
		}

		config.UpdateInfo(func(i *Info) error {
			i.Email = email
			i.Password = hashedPassword
			return nil
		})
	}

	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Domain = domain
		return nil
	})

	w.Redirect("/?success=settings")
}

func helpHandler(w *Web) {
	w.HTML()
}

func addPropertyHandler(w *Web) {
	name := strings.TrimSpace(w.r.FormValue("name"))
	domain := strings.TrimSpace(w.r.FormValue("domain"))

	if name == "" {
		name = "Unnamed Property"
	}

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimRight(domain, "/")

	if _, icann := publicsuffix.PublicSuffix(domain); !icann {
		w.Redirect("/?error=adding")
		return
	}

	property, err := config.AddProperty(name, domain)
	if err != nil {
		logger.Warn(err)
		w.Redirect("/?error=adding")
		return
	}

	w.Redirect("/property/snippet/%s?success=added", property.ID)
}

func deletePropertyHandler(w *Web) {
	propertyID := w.ps.ByName("property")
	if propertyID == "" {
		propertyID = w.r.FormValue("property")
	}
	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	if w.r.Method == "GET" {
		w.Property = property
		w.HTML()
		return
	}

	// Purge data
	if err := eventPurge(property.ID); err != nil {
		w.Redirect("/property/delete/%s?error=purge", property.ID)
	}

	if err := config.DeleteProperty(property.ID); err != nil {
		panic(err)
	}
	w.Redirect("/?success=removed")
}

func dashboardPropertyHandler(w *Web) {
	propertyID := w.ps.ByName("property")
	if propertyID == "" {
		propertyID = w.r.FormValue("property")
	}
	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	now := time.Now()

	if w.r.Method == "POST" {
		start, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("start"), now.Location())
		if start.IsZero() {
			start, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("start"), now.Location())
		}
		end, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("end"), now.Location())
		if end.IsZero() {
			end, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("end"), now.Location())
		}
		if start.IsZero() || end.IsZero() {
			w.Redirect("/property/dashboard/%s", property.ID)
			return
		}

		w.Redirect("/property/dashboard/%s?start=%d&end=%d", property.ID, start.Unix(), end.Unix())
		return
	}

	start, _ := strconv.ParseInt(w.r.FormValue("start"), 10, 64)
	end, _ := strconv.ParseInt(w.r.FormValue("end"), 10, 64)

	if start == 0 {
		start = now.AddDate(0, 0, -30).Unix()
	}
	if end == 0 || end > now.Unix() {
		end = now.Unix()
	}
	if start > end {
		w.Redirect("/property/dashboard/%s", property.ID)
		return
	}

	stat := NewStat(property.ID, start, end)

	//PagesChart: stat.PagesChart(""),
	w.Stats = Stats{
		VisitorsChart: stat.VisitorsChart(),
		Sources:       stat.Sources(),
		Pages:         stat.Pages(4),
		Referrers:     stat.Referrers(4),
		Platforms:     stat.Platforms(4),
		Events:        stat.Events(10, 1),
	}

	w.Property = property
	w.Start = start
	w.End = end
	w.HTML()
	return
}

func sourcesPropertyHandler(w *Web) {
	propertyID := w.ps.ByName("property")
	if propertyID == "" {
		propertyID = w.r.FormValue("property")
	}
	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	now := time.Now()

	if w.r.Method == "POST" {
		start, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("start"), now.Location())
		if start.IsZero() {
			start, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("start"), now.Location())
		}
		end, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("end"), now.Location())
		if end.IsZero() {
			end, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("end"), now.Location())
		}
		if start.IsZero() || end.IsZero() {
			w.Redirect("/property/sources/%s", property.ID)
			return
		}

		w.Redirect("/property/sources/%s?start=%d&end=%d", property.ID, start.Unix(), end.Unix())
		return
	}

	start, _ := strconv.ParseInt(w.r.FormValue("start"), 10, 64)
	end, _ := strconv.ParseInt(w.r.FormValue("end"), 10, 64)

	if start == 0 {
		start = now.AddDate(0, 0, -30).Unix()
	}
	if end == 0 || end > now.Unix() {
		end = now.Unix()
	}
	if start > end {
		w.Redirect("/property/sources/%s", property.ID)
		return
	}

	stat := NewStat(property.ID, start, end)
	w.Stats = Stats{
		Sources: stat.Sources(),
	}
	w.Property = property
	w.Start = start
	w.End = end
	w.HTML()
	return
}

func pagesPropertyHandler(w *Web) {
	propertyID := w.ps.ByName("property")
	if propertyID == "" {
		propertyID = w.r.FormValue("property")
	}
	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	now := time.Now()

	if w.r.Method == "POST" {
		start, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("start"), now.Location())
		if start.IsZero() {
			start, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("start"), now.Location())
		}
		end, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("end"), now.Location())
		if end.IsZero() {
			end, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("end"), now.Location())
		}
		if start.IsZero() || end.IsZero() {
			w.Redirect("/property/pages/%s", property.ID)
			return
		}

		w.Redirect("/property/pages/%s?start=%d&end=%d", property.ID, start.Unix(), end.Unix())
		return
	}

	start, _ := strconv.ParseInt(w.r.FormValue("start"), 10, 64)
	end, _ := strconv.ParseInt(w.r.FormValue("end"), 10, 64)

	if start == 0 {
		start = now.AddDate(0, 0, -30).Unix()
	}
	if end == 0 || end > now.Unix() {
		end = now.Unix()
	}
	if start > end {
		w.Redirect("/property/pages/%s", property.ID)
		return
	}

	stat := NewStat(property.ID, start, end)
	w.Stats = Stats{
		Pages: stat.Pages(100),
	}
	w.Property = property
	w.Start = start
	w.End = end
	w.HTML()
	return
}

func referrersPropertyHandler(w *Web) {
	propertyID := w.ps.ByName("property")
	if propertyID == "" {
		propertyID = w.r.FormValue("property")
	}
	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	now := time.Now()

	if w.r.Method == "POST" {
		start, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("start"), now.Location())
		if start.IsZero() {
			start, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("start"), now.Location())
		}
		end, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("end"), now.Location())
		if end.IsZero() {
			end, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("end"), now.Location())
		}
		if start.IsZero() || end.IsZero() {
			w.Redirect("/property/referrers/%s", property.ID)
			return
		}

		w.Redirect("/property/referrers/%s?start=%d&end=%d", property.ID, start.Unix(), end.Unix())
		return
	}

	start, _ := strconv.ParseInt(w.r.FormValue("start"), 10, 64)
	end, _ := strconv.ParseInt(w.r.FormValue("end"), 10, 64)

	if start == 0 {
		start = now.AddDate(0, 0, -30).Unix()
	}
	if end == 0 || end > now.Unix() {
		end = now.Unix()
	}
	if start > end {
		w.Redirect("/property/referrers/%s", property.ID)
		return
	}

	stat := NewStat(property.ID, start, end)
	w.Stats = Stats{
		Referrers: stat.Referrers(100),
	}
	w.Property = property
	w.Start = start
	w.End = end
	w.HTML()
	return
}

func platformsPropertyHandler(w *Web) {
	propertyID := w.ps.ByName("property")
	if propertyID == "" {
		propertyID = w.r.FormValue("property")
	}
	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	now := time.Now()

	if w.r.Method == "POST" {
		start, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("start"), now.Location())
		if start.IsZero() {
			start, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("start"), now.Location())
		}
		end, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("end"), now.Location())
		if end.IsZero() {
			end, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("end"), now.Location())
		}
		if start.IsZero() || end.IsZero() {
			w.Redirect("/property/platforms/%s", property.ID)
			return
		}

		w.Redirect("/property/platforms/%s?start=%d&end=%d", property.ID, start.Unix(), end.Unix())
		return
	}

	start, _ := strconv.ParseInt(w.r.FormValue("start"), 10, 64)
	end, _ := strconv.ParseInt(w.r.FormValue("end"), 10, 64)

	if start == 0 {
		start = now.AddDate(0, 0, -30).Unix()
	}
	if end == 0 || end > now.Unix() {
		end = now.Unix()
	}
	if start > end {
		w.Redirect("/property/platforms/%s", property.ID)
		return
	}

	stat := NewStat(property.ID, start, end)
	w.Stats = Stats{
		Platforms: stat.Platforms(100),
	}
	w.Property = property
	w.Start = start
	w.End = end
	w.HTML()
	return
}

func eventsPropertyHandler(w *Web) {
	propertyID := w.ps.ByName("property")
	if propertyID == "" {
		propertyID = w.r.FormValue("property")
	}
	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	now := time.Now()

	if w.r.Method == "POST" {
		start, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("start"), now.Location())
		if start.IsZero() {
			start, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("start"), now.Location())
		}
		end, _ := time.ParseInLocation("2006/01/02", w.r.FormValue("end"), now.Location())
		if end.IsZero() {
			end, _ = time.ParseInLocation("2006/1/2", w.r.FormValue("end"), now.Location())
		}
		if start.IsZero() || end.IsZero() {
			w.Redirect("/property/events/%s", property.ID)
			return
		}

		w.Redirect("/property/events/%s?start=%d&end=%d", property.ID, start.Unix(), end.Unix())
		return
	}

	limit := 20
	page, _ := strconv.Atoi(w.r.FormValue("page"))
	if page == 0 {
		page = 1
	}

	start, _ := strconv.ParseInt(w.r.FormValue("start"), 10, 64)
	end, _ := strconv.ParseInt(w.r.FormValue("end"), 10, 64)

	if start == 0 {
		start = now.AddDate(0, 0, -30).Unix()
	}
	if end == 0 || end > now.Unix() {
		end = now.Unix()
	}
	if start > end {
		w.Redirect("/property/events/%s", property.ID)
		return
	}

	stat := NewStat(property.ID, start, end)
	w.Stats = Stats{
		Events: stat.Events(limit, page),
	}
	w.Page = page
	w.Property = property
	w.Start = start
	w.End = end
	w.HTML()
	return
}

func snippetPropertyHandler(w *Web) {
	property, err := config.FindProperty(w.ps.ByName("property"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	w.Property = property
	w.HTML()
	return
}

func settingsPropertyHandler(w *Web) {
	propertyID := w.r.FormValue("property")
	if propertyID == "" {
		propertyID = w.ps.ByName("property")
	}

	property, err := config.FindProperty(propertyID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	if w.r.Method == "GET" {
		w.Property = property
		w.HTML()
		return
	}

	name := strings.TrimSpace(w.r.FormValue("name"))
	domain := strings.TrimSpace(w.r.FormValue("domain"))

	if name == "" {
		name = "Unnamed Property"
	}

	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimRight(domain, "/")

	if _, icann := publicsuffix.PublicSuffix(domain); !icann {
		w.Redirect("/property/settings/%s", property.ID)
		return
	}

	config.UpdateProperty(property.ID, func(p *Property) error {
		p.Name = name
		p.Domain = domain
		return nil
	})

	w.Redirect("/property/settings/%s?success=changes", property.ID)
}

/*
func pageviewChartHandler(w *Web) {
	property, err := config.FindProperty(w.ps.ByName("property"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	start, _ := strconv.ParseInt(w.r.FormValue("start"), 10, 64)
	end, _ := strconv.ParseInt(w.r.FormValue("end"), 10, 64)

	stat := NewStat(property.ID, start, end)
	xvalues := []time.Time{}
	yvalues := []float64{}

	for _, pv := range stat.PageViewChart(start, end, "") {
		xvalues = append(xvalues, pv.Time)
		yvalues = append(yvalues, float64(pv.Hits))
		//logger.Printf("CHART VALUE X/Y %s %d", pv.Time, pv.Hits)
	}

	graph := chart.Chart{
		XAxis: chart.XAxis{
			Style: chart.StyleShow(),
		},
		Series: []chart.Series{
			chart.TimeSeries{
				XValues: xvalues,
				YValues: yvalues,
			},
		},
	}

	w.w.Header().Set("Content-Type", "image/png")
	graph.Render(chart.PNG, w.w)
}
*/
