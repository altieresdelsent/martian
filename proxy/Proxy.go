package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/altieres/martian/v3"
	mapi "github.com/altieres/martian/v3/api"
	"github.com/altieres/martian/v3/cors"
	"github.com/altieres/martian/v3/fifo"
	"github.com/altieres/martian/v3/har"
	"github.com/altieres/martian/v3/httpspec"
	mlog "github.com/altieres/martian/v3/log"
	"github.com/altieres/martian/v3/marbl"
	"github.com/altieres/martian/v3/martianhttp"
	"github.com/altieres/martian/v3/martianlog"
	"github.com/altieres/martian/v3/mitm"
	"github.com/altieres/martian/v3/servemux"
	"github.com/altieres/martian/v3/trafficshape"
	"github.com/altieres/martian/v3/verify"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

type ProxyService struct {
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
	DsProxyURL       *string
	Level            *int
	proxyTcpListener net.Listener
	internalProxy    *martian.Proxy
	apiTcpListener   net.Listener
	apiHttpServer    *http.ServeMux
}

func (proxy *ProxyService) Start() {

	flag.Parse()
	mlog.SetLevel(*proxy.Level)

	proxy.internalProxy = martian.NewProxy()
	var err error

	proxy.proxyTcpListener, err = net.Listen("tcp", *proxy.Addr)
	if err != nil {
		log.Fatal(err)
	}

	proxy.apiTcpListener, err = net.Listen("tcp", *proxy.ApiAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("martian: starting proxy on %s and api on %s", proxy.proxyTcpListener.Addr().String(), proxy.apiTcpListener.Addr().String())

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *proxy.SkipTLSVerify,
		},
	}
	proxy.internalProxy.SetRoundTripper(tr)

	if *proxy.DsProxyURL != "" {
		u, err := url.Parse(*proxy.DsProxyURL)
		if err != nil {
			log.Fatal(err)
		}
		proxy.internalProxy.SetDownstreamProxy(u)
	}

	proxy.apiHttpServer = http.NewServeMux()

	var x509c *x509.Certificate
	var priv interface{}

	if *proxy.GenerateCA {
		var err error
		x509c, priv, err = mitm.NewAuthority("martian.proxy", "Martian Authority", 30*24*time.Hour)
		if err != nil {
			log.Fatal(err)
		}
	} else if *proxy.Cert != "" && *proxy.Key != "" {
		tlsc, err := tls.LoadX509KeyPair(*proxy.Cert, *proxy.Key)
		if err != nil {
			log.Fatal(err)
		}
		priv = tlsc.PrivateKey

		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
	}

	if x509c != nil && priv != nil {
		mc, err := mitm.NewConfig(x509c, priv)
		if err != nil {
			log.Fatal(err)
		}

		mc.SetValidity(*proxy.Validity)
		mc.SetOrganization(*proxy.Organization)
		mc.SkipTLSVerify(*proxy.SkipTLSVerify)

		proxy.internalProxy.SetMITM(mc)

		// Expose certificate authority.
		ah := martianhttp.NewAuthorityHandler(x509c)
		proxy.configure("/authority.cer", ah, proxy.apiHttpServer)

		// Start TLS listener for transparent MITM.
		tl, err := net.Listen("tcp", *proxy.TlsAddr)
		if err != nil {
			log.Fatal(err)
		}

		go proxy.internalProxy.Serve(tls.NewListener(tl, mc.TLS()))
	}

	stack, fg := httpspec.NewStack("martian")

	// wrap stack in a group so that we can forward API requests to the API port
	// before the httpspec modifiers which include the via modifier which will
	// trip loop detection
	topg := fifo.NewGroup()

	// Redirect API traffic to API server.
	if *proxy.ApiAddr != "" {
		addrParts := strings.Split(proxy.apiTcpListener.Addr().String(), ":")
		apip := addrParts[len(addrParts)-1]
		port, err := strconv.Atoi(apip)
		if err != nil {
			log.Fatal(err)
		}
		host := strings.Join(addrParts[:len(addrParts)-1], ":")

		// Forward traffic that pattern matches in http.DefaultServeMux
		apif := servemux.NewFilter(proxy.apiHttpServer)
		apif.SetRequestModifier(mapi.NewForwarder(host, port))
		topg.AddRequestModifier(apif)
	}
	topg.AddRequestModifier(stack)
	topg.AddResponseModifier(stack)

	proxy.internalProxy.SetRequestModifier(topg)
	proxy.internalProxy.SetResponseModifier(topg)

	m := martianhttp.NewModifier()
	fg.AddRequestModifier(m)
	fg.AddResponseModifier(m)

	if *proxy.HarLogging {
		hl := har.NewLogger()
		muxf := servemux.NewFilter(proxy.apiHttpServer)
		// Only append to HAR logs when the requests are not API requests,
		// that is, they are not matched in http.DefaultServeMux
		muxf.RequestWhenFalse(hl)
		muxf.ResponseWhenFalse(hl)

		stack.AddRequestModifier(muxf)
		stack.AddResponseModifier(muxf)

		proxy.configure("/logs", har.NewExportHandler(hl), proxy.apiHttpServer)
		proxy.configure("/logs/reset", har.NewResetHandler(hl), proxy.apiHttpServer)
	}

	logger := martianlog.NewLogger()
	logger.SetDecode(true)

	stack.AddRequestModifier(logger)
	stack.AddResponseModifier(logger)

	if *proxy.MarblLogging {
		lsh := marbl.NewHandler()
		lsm := marbl.NewModifier(lsh)
		muxf := servemux.NewFilter(proxy.apiHttpServer)
		muxf.RequestWhenFalse(lsm)
		muxf.ResponseWhenFalse(lsm)
		stack.AddRequestModifier(muxf)
		stack.AddResponseModifier(muxf)

		// retrieve binary marbl logs
		proxy.apiHttpServer.Handle("/binlogs", lsh)
	}

	// Configure modifiers.
	proxy.configure("/configure", m, proxy.apiHttpServer)

	// Verify assertions.
	vh := verify.NewHandler()
	vh.SetRequestVerifier(m)
	vh.SetResponseVerifier(m)
	proxy.configure("/verify", vh, proxy.apiHttpServer)

	// Reset verifications.
	rh := verify.NewResetHandler()
	rh.SetRequestVerifier(m)
	rh.SetResponseVerifier(m)
	proxy.configure("/verify/reset", rh, proxy.apiHttpServer)

	if *proxy.TrafficShaping {
		tsl := trafficshape.NewListener(proxy.proxyTcpListener)
		tsh := trafficshape.NewHandler(tsl)
		proxy.configure("/shape-traffic", tsh, proxy.apiHttpServer)

		proxy.proxyTcpListener = tsl
	}

	go proxy.internalProxy.Serve(proxy.proxyTcpListener)

	go http.Serve(proxy.apiTcpListener, proxy.apiHttpServer)
}

func (proxy *ProxyService) Stop() (error, error) {
	proxy.internalProxy.Close()
	errProxy := proxy.proxyTcpListener.Close()
	errApi := proxy.apiTcpListener.Close()
	return errProxy, errApi
}

// configure installs a configuration handler at path.
func (proxy *ProxyService) configure(pattern string, handler http.Handler, mux *http.ServeMux) {
	if *proxy.AllowCORS {
		handler = cors.NewHandler(handler)
	}

	// register handler for martian.proxy to be forwarded to
	// local API server
	mux.Handle(path.Join(*proxy.Api, pattern), handler)

	// register handler for local API server
	p := path.Join("localhost"+*proxy.ApiAddr, pattern)
	mux.Handle(p, handler)
	pNoDoor := path.Join("localhost", pattern)
	mux.Handle(pNoDoor, handler)
	pIpv6 := path.Join(":"+*proxy.ApiAddr, pattern)
	mux.Handle(pIpv6, handler)
	pIpv6NoDoor := path.Join("::", pattern)
	mux.Handle(pIpv6NoDoor, handler)
}
