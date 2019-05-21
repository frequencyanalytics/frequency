package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var (
	ErrPropertyNotFound = errors.New("property not found")
)

type Property struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Domain  string    `json:"domain"`
	Created time.Time `json:"created"`
}

type Info struct {
	Email      string `json:"email"`
	Password   []byte `json:"password"`
	Secret     string `json:"secret"`
	Configured bool   `json:"configure"`
	Domain     string `json:"domain"`
	HashKey    string `json:"hash_key"`
	BlockKey   string `json:"block_key"`
	Location   string `json:"location"`
	SAML       struct {
		IDPMetadata string `json:"idp_metadata"`
		PrivateKey  []byte `json:"private_key"`
		Certificate []byte `json:"certificate"`
	} `json:"saml"`
	Mail struct {
		From     string `json:"from"`
		Server   string `json:"server"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"mail"`
}

type Config struct {
	mu       sync.RWMutex
	filename string

	Info *Info `json:"info"`

	Properties []*Property `json:"properties"`

	Modified time.Time `json:"modified"`
}

func NewConfig(filename string) (*Config, error) {
	filename = filepath.Join(datadir, filename)
	c := &Config{filename: filename}
	b, err := ioutil.ReadFile(filename)

	// Create new config with defaults
	if os.IsNotExist(err) {
		c.Info = &Info{
			HashKey:  randomString(32),
			BlockKey: randomString(32),
			Location: "UTC",
		}
		return c, c.generateSAMLKeyPair()
	}
	if err != nil {
		return nil, err
	}

	// Open existing config
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("invalid config %q: %s", filename, err)
	}

	if c.Info.Location == "" {
		c.Info.Location = "UTC"
	}
	if len(c.Info.SAML.PrivateKey) == 0 || len(c.Info.SAML.Certificate) == 0 {
		if err := c.generateSAMLKeyPair(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Config) Lock() {
	c.mu.Lock()
}

func (c *Config) Unlock() {
	c.mu.Unlock()
}

func (c *Config) RLock() {
	c.mu.RLock()
}

func (c *Config) RUnlock() {
	c.mu.RUnlock()
}

func (c *Config) DeleteProperty(id string) error {
	c.Lock()
	defer c.Unlock()

	var properties []*Property
	for _, p := range c.Properties {
		if p.ID == id {
			continue
		}
		properties = append(properties, p)
	}
	c.Properties = properties
	return c.save()
}

func (c *Config) UpdateProperty(id string, fn func(*Property) error) error {
	c.Lock()
	defer c.Unlock()
	p, err := c.findProperty(id)
	if err != nil {
		return err
	}
	if err := fn(p); err != nil {
		return err
	}
	return c.save()
}

func (c *Config) AddProperty(name, domain string) (Property, error) {
	c.Lock()
	defer c.Unlock()

	var id string
	for {
		n := randomString(16)
		if _, err := c.findProperty(n); err == ErrPropertyNotFound {
			id = n
			break
		}
	}
	property := Property{
		ID:      id,
		Name:    name,
		Domain:  domain,
		Created: time.Now(),
	}
	c.Properties = append(c.Properties, &property)
	return property, c.save()
}

func (c *Config) FindProperty(id string) (Property, error) {
	c.RLock()
	defer c.RUnlock()
	u, err := c.findProperty(id)
	if err != nil {
		return Property{}, err
	}
	return *u, nil
}

func (c *Config) findProperty(id string) (*Property, error) {
	for _, u := range c.Properties {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, ErrPropertyNotFound
}

func (c *Config) ListProperties() (properties []Property) {
	c.RLock()
	defer c.RUnlock()
	for _, p := range c.listProperties() {
		properties = append(properties, *p)
	}
	return
}

func (c *Config) listProperties() (properties []*Property) {
	for _, p := range c.Properties {
		properties = append(properties, p)
	}
	sort.Slice(properties, func(i, j int) bool { return properties[i].Created.After(properties[j].Created) })
	return
}

func (c *Config) FindInfo() Info {
	c.RLock()
	defer c.RUnlock()
	return *c.Info
}

func (c *Config) UpdateInfo(fn func(*Info) error) error {
	c.Lock()
	defer c.Unlock()
	if err := fn(c.Info); err != nil {
		return err
	}
	return c.save()
}

func (c *Config) save() error {
	b, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}
	return overwrite(c.filename, b, 0644)
}

func (c *Config) generateSAMLKeyPair() error {
	// Generate private key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Generate the certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   httpHost,
			Organization: []string{"Frequency"},
		},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	// Generate private key PEM block.
	c.Info.SAML.PrivateKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Generate certificate PEM block.
	c.Info.SAML.Certificate = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return c.save()
}
