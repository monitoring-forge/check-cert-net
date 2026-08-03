package main

import (
	"bufio"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

type certInfo struct {
	notAfter *time.Time
	subjects []string
}

var layout = "Jan 2 15:04:05 2006 MST"

func daysRemaining(cert *certInfo) int64 {
	return int64(cert.notAfter.Sub(time.Now().UTC()).Hours() / 24)
}

func (opt *Opt) parseCertInfo(r io.Reader) (*certInfo, error) {
	s := bufio.NewScanner(r)
	subjects := make([]string, 0)
	var notAfter *time.Time
	prev := ""
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		subjects = appendSubject(subjects, l)
		if t, err := parseNotAfter(l); err != nil {
			return nil, err
		} else if t != nil {
			notAfter = t
		}
		subjects = appendSAN(subjects, prev, l)
		prev = l
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("error scanning output: %w", err)
	}
	if notAfter == nil {
		return nil, fmt.Errorf("could not find notAfter in result")
	}
	return &certInfo{notAfter, subjects}, nil
}

func appendSubject(subjects []string, l string) []string {
	if strings.HasPrefix(l, "Subject: CN=") || strings.HasPrefix(l, "Subject CN = ") {
		cn := strings.TrimSpace(strings.SplitN(l, "=", 2)[1])
		subjects = append(subjects, cn)
	}
	return subjects
}

func parseNotAfter(l string) (*time.Time, error) {
	if strings.Index(l, "Not After : ") != 0 {
		return nil, nil
	}
	na, err := time.Parse(layout, l[len("Not After : "):])
	if err != nil {
		return nil, fmt.Errorf("%w:%s", err, l)
	}
	return &na, nil
}

func appendSAN(subjects []string, prev, l string) []string {
	if strings.Index(prev, "Subject Alternative Name:") <= 0 || strings.Index(l, "DNS:") != 0 {
		return subjects
	}
	for d := range strings.SplitSeq(l, ",") {
		d2 := strings.TrimSpace(d)
		if strings.Index(d2, "DNS:") != 0 {
			continue
		}
		d3 := d2[len("DNS:"):]
		if !slices.Contains(subjects, d3) {
			subjects = append(subjects, d3)
		}
	}
	return subjects
}

func (opt *Opt) getCertInfo() (*certInfo, error) {
	r, err := opt.runCommand()
	if err != nil {
		return nil, err
	}
	return opt.parseCertInfo(r)
}

func (opt *Opt) verifyServerName(cert *certInfo) error {
	if !opt.VerifyServerName {
		return nil
	}
	verifiedHostname := false
	for _, d := range cert.subjects {
		if strings.Index(d, "*.") == 0 {
			d2 := strings.Split(d, ".")
			s2 := strings.Split(opt.ServerName, ".")
			if strings.Join(d2[1:], ".") == strings.Join(s2[1:], ".") {
				verifiedHostname = true
				break
			}
		} else if d == opt.ServerName {
			verifiedHostname = true
			break
		}
	}
	if !verifiedHostname {
		return fmt.Errorf("servername:%s is not included in %s", opt.ServerName, strings.Join(cert.subjects, ","))
	}
	return nil
}
