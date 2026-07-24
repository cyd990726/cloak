package cloaker

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

type countryGate struct {
	db *geoip2.Reader
}

func newCountryGate(path string) (*countryGate, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &countryGate{db: db}, nil
}

func (g *countryGate) Country(ip net.IP) string {
	code, _ := g.CheckCountry(ip)
	return code
}

func (g *countryGate) CheckCountry(ip net.IP) (string, bool) {
	if ip == nil || g.db == nil {
		return "", true
	}
	record, err := g.db.Country(ip)
	if err != nil {
		return "", true
	}
	code := record.Country.IsoCode
	if code == "" {
		return "", true
	}
	return code, false
}

func (g *countryGate) Close() error {
	if g.db != nil {
		return g.db.Close()
	}
	return nil
}
