package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/kazeburo/check-cert-net/execpipe"
)

func fmtString(s string) string {
	out := strings.TrimRight(s, "\n")
	out = strings.NewReplacer(
		"\r\n", "\\r\\n",
		"\r", "\\r",
		"\n", "\\n",
	).Replace(out)
	return out
}

func (opt *Opt) buildOpenSSLCommand() ([]string, error) {
	cmd := []string{"openssl", "s_client"}
	if opt.ServerName != "" {
		cmd = append(cmd, "-servername")
		cmd = append(cmd, opt.ServerName)
	}
	cmd = append(cmd, "-connect")
	cmd = append(cmd, net.JoinHostPort(opt.Host, opt.Port))

	if opt.ECDSA {
		cmd = append(cmd, "-cipher")
		cmd = append(cmd, "aECDSA")
	} else if opt.RSA {
		cmd = append(cmd, "-cipher")
		cmd = append(cmd, "aRSA")
	}

	return cmd, nil
}

func (opt *Opt) buildOpenSSLX509Command() []string {
	return []string{"openssl", "x509", "-noout", "-text"}
}

func (opt *Opt) runCommand() (io.Reader, error) {
	sClientCmd, err := opt.buildOpenSSLCommand()
	if err != nil {
		return nil, err
	}
	x509Cmd := opt.buildOpenSSLX509Command()
	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()
	var out bytes.Buffer
	var errBuf bytes.Buffer
	err = execpipe.Command(
		ctx,
		&out,
		&errBuf,
		[]string{"echo", "QUIT"},
		sClientCmd,
		x509Cmd,
	)
	if err != nil {
		return nil, fmt.Errorf("%w:%s", err, fmtString(errBuf.String()))
	}

	return &out, nil
}
