package service

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"github.com/altieresdelsent/martian/v3"
	mapi "github.com/altieresdelsent/martian/v3/api"
	"github.com/altieresdelsent/martian/v3/cors"
	"github.com/altieresdelsent/martian/v3/fifo"
	"github.com/altieresdelsent/martian/v3/har"
	"github.com/altieresdelsent/martian/v3/httpspec"
	mlog "github.com/altieresdelsent/martian/v3/log"
	"github.com/altieresdelsent/martian/v3/marbl"
	"github.com/altieresdelsent/martian/v3/martianhttp"
	"github.com/altieresdelsent/martian/v3/martianlog"
	"github.com/altieresdelsent/martian/v3/mitm"
	"github.com/altieresdelsent/martian/v3/servemux"
	"github.com/altieresdelsent/martian/v3/trafficshape"
	"github.com/altieresdelsent/martian/v3/verify"
	"github.com/altieresdelsent/pointer"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	Addr             *string
	ApiAddr          *string
	TlsAddr          *string
	Api              *string
	GenerateCA       *bool
	Cert             *string
	Key              *string
	Organization     *string
	Validity         *time.Duration
	AllowCORS        *bool
	HarLogging       *bool
	MarblLogging     *bool
	TrafficShaping   *bool
	SkipTLSVerify    *bool
	DsProxyURL       func(*http.Request) (*url.URL, error)
	Level            *int
	proxyTcpListener net.Listener
	internalProxy    *martian.Proxy
	stack            *fifo.Group
	fg               *fifo.Group
	apiTcpListener   net.Listener
	apiHttpServer    *http.ServeMux
	harLooger        *har.Logger
}

func (service *Service) HasHarLogger() bool {
	return service.harLooger != nil
}
func (service *Service) ProxyURL() string {
	return "http://" + service.apiTcpListener.Addr().String()
}

func (service *Service) ExportHarLogger() ([]byte, error) {
	if service.HasHarLogger() {
		harLog := service.harLooger.Export()
		return json.Marshal(harLog)
	}
	return nil, errors.New("no har logger")

}

func (service *Service) ResetHarLogger() error {
	if service.HasHarLogger() {
		service.harLooger.Reset()
		return nil
	}
	return errors.New("no har logger")
}

func (service *Service) ExportAndResetHarLogger() ([]byte, error) {
	if service.HasHarLogger() {
		harLog := service.harLooger.Export()
		return json.Marshal(harLog)
	}
	return nil, errors.New("no har logger")
}

func (service *Service) Initialize() {
	if service.Addr == nil || *service.Addr == "" {
		service.Addr = pointer.Pointer(":8080")
	}

	if service.TlsAddr == nil || *service.TlsAddr == "" {
		service.TlsAddr = pointer.Pointer(":4443")
	}
	if service.GenerateCA == nil {
		service.GenerateCA = pointer.Pointer(true)
	}
	if service.Cert == nil || *service.Cert == "" {
		service.Cert = pointer.Pointer("")
	}
	if service.Key == nil || *service.Key == "" {
		service.Key = pointer.Pointer("")
	}
	if service.Organization == nil || *service.Organization == "" {
		service.Organization = pointer.Pointer("Martian Proxy")
	}
	if service.Validity == nil || *service.Addr == "" {
		service.Validity = pointer.Pointer(time.Hour)
	}
	if service.AllowCORS == nil {
		service.AllowCORS = pointer.Pointer(false)
	}

	if service.HarLogging == nil {
		service.HarLogging = pointer.Pointer(false)
	}

	if service.MarblLogging == nil {
		service.MarblLogging = pointer.Pointer(false)
	}

	if service.TrafficShaping == nil {
		service.TrafficShaping = pointer.Pointer(false)
	}

	if service.SkipTLSVerify == nil {
		service.SkipTLSVerify = pointer.Pointer(false)
	}

	if service.Level == nil {
		service.Level = pointer.Pointer(1)
	}
	service.internalProxy = martian.NewProxy()
	service.internalProxy.SetTimeout(100 * time.Second)
	service.stack, service.fg = httpspec.NewStack("martian")
}
func (service *Service) Start() error {

	flag.Parse()
	mlog.SetLevel(*service.Level)

	var err error

	service.proxyTcpListener, err = net.Listen("tcp", *service.Addr)
	if err != nil {
		return err
	}

	if service.ApiAddr != nil {
		service.apiTcpListener, err = net.Listen("tcp", *service.ApiAddr)
		if err != nil {
			return err
		}
	}

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   200 * time.Second,
			KeepAlive: 200 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   200 * time.Second,
		ExpectContinueTimeout: 200 * time.Second,
		IdleConnTimeout:       200 * time.Second,
		ResponseHeaderTimeout: 200 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *service.SkipTLSVerify,
		},
	}
	service.internalProxy.SetRoundTripper(tr)

	if (*service).DsProxyURL != nil {
		service.internalProxy.SetDownstreamProxy(service.DsProxyURL)
	}

	service.apiHttpServer = http.NewServeMux()

	var x509c *x509.Certificate
	var priv interface{}

	if *service.GenerateCA {
		var err error
		x509c, priv, err = mitm.NewAuthority("martian.proxy", "Martian Authority", 30*24*time.Hour)
		if err != nil {
			return err
		}
	} else if *service.Cert != "" && *service.Key != "" {
		tlsc, err := tls.LoadX509KeyPair(*service.Cert, *service.Key)
		if err != nil {
			return err
		}
		priv = tlsc.PrivateKey

		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			return err
		}
	}

	if x509c != nil && priv != nil {
		mc, err := mitm.NewConfig(x509c, priv)
		if err != nil {
			return err
		}

		mc.SetValidity(*service.Validity)
		mc.SetOrganization(*service.Organization)
		mc.SkipTLSVerify(*service.SkipTLSVerify)

		service.internalProxy.SetMITM(mc)

		// Expose certificate authority.
		ah := martianhttp.NewAuthorityHandler(x509c)
		service.configure("/authority.cer", ah)

		// Start TLS listener for transparent MITM.
		tl, err := net.Listen("tcp", *service.TlsAddr)
		if err != nil {
			return err
		}

		go service.internalProxy.Serve(tls.NewListener(tl, mc.TLS()))
	}

	// wrap stack in a group so that we can forward API requests to the API port
	// before the httpspec modifiers which include the via modifier which will
	// trip loop detection
	topg := fifo.NewGroup()

	// Redirect API traffic to API server.
	if service.ApiAddr != nil && *service.ApiAddr != "" {
		addrParts := strings.Split(service.apiTcpListener.Addr().String(), ":")
		apip := addrParts[len(addrParts)-1]
		port, err := strconv.Atoi(apip)
		if err != nil {
			return err
		}
		host := strings.Join(addrParts[:len(addrParts)-1], ":")

		// Forward traffic that pattern matches in http.DefaultServeMux
		apif := servemux.NewFilter(service.apiHttpServer)
		apif.SetRequestModifier(mapi.NewForwarder(host, port))
		topg.AddRequestModifier(apif)
	}
	topg.AddRequestModifier(service.stack)
	topg.AddResponseModifier(service.stack)

	service.internalProxy.SetRequestModifier(topg)
	service.internalProxy.SetResponseModifier(topg)

	m := martianhttp.NewModifier()
	service.fg.AddRequestModifier(m)
	service.fg.AddResponseModifier(m)

	if *service.HarLogging {
		hl := har.NewLogger()
		muxf := servemux.NewFilter(service.apiHttpServer)
		// Only append to HAR logs when the requests are not API requests,
		// that is, they are not matched in http.DefaultServeMux
		muxf.RequestWhenFalse(hl)
		muxf.ResponseWhenFalse(hl)

		service.stack.AddRequestModifier(muxf)
		service.stack.AddResponseModifier(muxf)

		service.configure("/logs", har.NewExportHandler(hl))
		service.configure("/logs/reset", har.NewResetHandler(hl))
	}

	logger := martianlog.NewLogger()
	logger.SetDecode(true)

	service.stack.AddRequestModifier(logger)
	service.stack.AddResponseModifier(logger)

	if *service.MarblLogging {
		lsh := marbl.NewHandler()
		lsm := marbl.NewModifier(lsh)
		muxf := servemux.NewFilter(service.apiHttpServer)
		muxf.RequestWhenFalse(lsm)
		muxf.ResponseWhenFalse(lsm)
		service.stack.AddRequestModifier(muxf)
		service.stack.AddResponseModifier(muxf)

		// retrieve binary marbl logs
		service.apiHttpServer.Handle("/binlogs", lsh)
	}

	// Configure modifiers.
	service.configure("/configure", m)

	// Verify assertions.
	vh := verify.NewHandler()
	vh.SetRequestVerifier(m)
	vh.SetResponseVerifier(m)
	service.configure("/verify", vh)

	// Reset verifications.
	rh := verify.NewResetHandler()
	rh.SetRequestVerifier(m)
	rh.SetResponseVerifier(m)
	service.configure("/verify/reset", rh)

	if *service.TrafficShaping {
		tsl := trafficshape.NewListener(service.proxyTcpListener)
		tsh := trafficshape.NewHandler(tsl)
		service.configure("/shape-traffic", tsh)

		service.proxyTcpListener = tsl
	}

	go service.internalProxy.Serve(service.proxyTcpListener)
	if service.apiTcpListener != nil {
		go http.Serve(service.apiTcpListener, service.apiHttpServer)
	}
	return nil
}

func (service *Service) Stop() (error, error) {
	if service.internalProxy != nil {
		service.internalProxy.Close()
	}
	var errProxy, errApi error
	if service.proxyTcpListener != nil {
		errProxy = service.proxyTcpListener.Close()
	}
	if service.apiTcpListener != nil {
		errApi = service.apiTcpListener.Close()
	}
	return errProxy, errApi
}

// configure installs a configuration handler at path.
func (service *Service) configure(pattern string, handler http.Handler) {
	if service.apiTcpListener == nil {
		return
	}
	if *service.AllowCORS {
		handler = cors.NewHandler(handler)
	}

	// register handler for martian.proxy to be forwarded to
	// local API server
	service.apiHttpServer.Handle(path.Join(*service.Api, pattern), handler)

	// register handler for local API server
	p := path.Join("localhost"+*service.ApiAddr, pattern)
	service.apiHttpServer.Handle(p, handler)
	pNoDoor := path.Join("localhost", pattern)
	service.apiHttpServer.Handle(pNoDoor, handler)
	pIpv6 := path.Join(":"+*service.ApiAddr, pattern)
	service.apiHttpServer.Handle(pIpv6, handler)
	pIpv6NoDoor := path.Join("::", pattern)
	service.apiHttpServer.Handle(pIpv6NoDoor, handler)
}

// SetRequestModifier sets the request modifier.
func (service *Service) AddRequestModifier(reqmod martian.RequestModifier) {
	service.stack.AddRequestModifier(reqmod)
}

// SetResponseModifier sets the response modifier.
func (service *Service) AddResponseModifier(resmod martian.ResponseModifier) {
	service.stack.AddResponseModifier(resmod)
}

// SetResponseModifier sets the response modifier.
func (service *Service) SetRoundTripModifier(roundTripModifier martian.RoundTripModifier) {
	service.internalProxy.SetRoundTripModifier(roundTripModifier)
}
