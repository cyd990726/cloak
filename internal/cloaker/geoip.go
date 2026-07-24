package cloaker

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type maxMindLookup struct {
	db *geoip2.Reader
}

func newMaxMindLookup(path string) (*maxMindLookup, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &maxMindLookup{db: db}, nil
}

func (m *maxMindLookup) Lookup(ip net.IP) (asn string, org string, err error) {
	record, err := m.db.ASN(ip)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("AS%d", record.AutonomousSystemNumber), record.AutonomousSystemOrganization, nil
}

func (m *maxMindLookup) Close() error {
	return m.db.Close()
}
