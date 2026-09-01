package main

import (
	"fmt"
	"os"
	"time"

	"github.com/mackerelio/checkers"
	"github.com/monitoring-forge/flagrun"
)

var version string

type Opt struct {
	Host             string        `short:"H" long:"host" default:"localhost" description:"Hostname"`
	Port             string        `short:"p" long:"port" default:"443" description:"Port"`
	ServerName       string        `long:"servername" default:"" description:"servername in ClientHello"`
	VerifyServerName bool          `long:"verify-servername" description:"verify servername"`
	Timeout          time.Duration `long:"timeout" default:"5s" description:"Timeout to connect to server"`
	RSA              bool          `long:"rsa" description:"Preferred aRSA cipher to use"`
	ECDSA            bool          `long:"ecdsa" description:"Preferred aECDSA cipher to use"`
	Crit             int64         `short:"c" long:"critical" default:"14" description:"The critical threshold in days before expiry"`
	Warn             int64         `short:"w" long:"warning" default:"30" description:"The threshold in days before expiry"`
	Version          bool          `short:"v" long:"version" description:"Show version"`
}

func (opt *Opt) Run(_ []string) *checkers.Checker {
	if opt.RSA && opt.ECDSA {
		return checkers.Unknown("cannot use --rsa and --ecdsa at the same time")
	}

	cert, err := opt.getCertInfo()
	if err != nil {
		return checkers.Critical(err.Error())
	}
	if err := opt.verifyServerName(cert); err != nil {
		return checkers.Critical(err.Error())
	}

	daysRemain := daysRemaining(cert)
	msg := fmt.Sprintf("Expiration date: %s, %d days remaining", cert.notAfter.Format("2006-01-02"), daysRemain)

	if daysRemain < opt.Crit {
		return checkers.Critical(msg)
	} else if daysRemain < opt.Warn {
		return checkers.Warning(msg)
	}
	return checkers.Ok(msg)
}

func main() {
	os.Exit(flagrun.Check(&Opt{}, flagrun.Version(version)))
}
