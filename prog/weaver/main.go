package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/davecheney/profile"
	"github.com/docker/docker/pkg/mflag"
	"github.com/gorilla/mux"
	. "github.com/weaveworks/weave/common"
	"github.com/weaveworks/weave/common/docker"
	"github.com/weaveworks/weave/ipam"
	weavenet "github.com/weaveworks/weave/net"
	"github.com/weaveworks/weave/net/address"
	weave "github.com/weaveworks/weave/router"
)

var version = "(unreleased version)"

func main() {
	procs := runtime.NumCPU()
	// packet sniffing can block an OS thread, so we need one thread
	// for that plus at least one more.
	if procs < 2 {
		procs = 2
	}
	runtime.GOMAXPROCS(procs)

	var (
		config       weave.Config
		justVersion  bool
		ifaceName    string
		routerName   string
		nickName     string
		password     string
		wait         int
		pktdebug     bool
		logLevel     string
		prof         string
		bufSzMB      int
		noDiscovery  bool
		httpAddr     string
		iprangeCIDR  string
		ipsubnetCIDR string
		peerCount    int
		apiPath      string
		peers        []string
		iface        *net.Interface
	)

	mflag.BoolVar(&justVersion, []string{"#version", "-version"}, false, "print version and exit")
	mflag.IntVar(&config.Port, []string{"#port", "-port"}, weave.Port, "router port")
	mflag.StringVar(&ifaceName, []string{"#iface", "-iface"}, "", "name of interface to capture/inject from (disabled if blank)")
	mflag.StringVar(&routerName, []string{"#name", "-name"}, "", "name of router (defaults to MAC of interface)")
	mflag.StringVar(&nickName, []string{"#nickname", "-nickname"}, "", "nickname of peer (defaults to hostname)")
	mflag.StringVar(&password, []string{"#password", "-password"}, "", "network password")
	mflag.IntVar(&wait, []string{"#wait", "-wait"}, -1, "number of seconds to wait for interface to come up (0=don't wait, -1=wait forever)")
	mflag.StringVar(&logLevel, []string{"-log-level"}, "info", "logging level (debug, info, warning, error)")
	mflag.BoolVar(&pktdebug, []string{"#pktdebug", "#-pktdebug", "-pkt-debug"}, false, "enable per-packet debug logging")
	mflag.StringVar(&prof, []string{"#profile", "-profile"}, "", "enable profiling and write profiles to given path")
	mflag.IntVar(&config.ConnLimit, []string{"#connlimit", "#-connlimit", "-conn-limit"}, 30, "connection limit (0 for unlimited)")
	mflag.BoolVar(&noDiscovery, []string{"#nodiscovery", "#-nodiscovery", "-no-discovery"}, false, "disable peer discovery")
	mflag.IntVar(&bufSzMB, []string{"#bufsz", "-bufsz"}, 8, "capture buffer size in MB")
	mflag.StringVar(&httpAddr, []string{"#httpaddr", "#-httpaddr", "-http-addr"}, fmt.Sprintf(":%d", weave.HTTPPort), "address to bind HTTP interface to (disabled if blank, absolute path indicates unix domain socket)")
	mflag.StringVar(&iprangeCIDR, []string{"#iprange", "#-iprange", "-ipalloc-range"}, "", "IP address range reserved for automatic allocation, in CIDR notation")
	mflag.StringVar(&ipsubnetCIDR, []string{"#ipsubnet", "#-ipsubnet", "-ipalloc-default-subnet"}, "", "subnet to allocate within by default, in CIDR notation")
	mflag.IntVar(&peerCount, []string{"#initpeercount", "#-initpeercount", "-init-peer-count"}, 0, "number of peers in network (for IP address allocation)")
	mflag.StringVar(&apiPath, []string{"#api", "-api"}, "unix:///var/run/docker.sock", "Path to Docker API socket")
	mflag.Parse()
	peers = mflag.Args()

	SetLogLevel(logLevel)
	if justVersion {
		fmt.Printf("weave router %s\n", version)
		os.Exit(0)
	}

	Log.Println("Command line options:", options())
	Log.Println("Command line peers:", peers)

	var err error

	if ifaceName != "" {
		iface, err := weavenet.EnsureInterface(ifaceName, wait)
		if err != nil {
			Log.Fatal(err)
		}

		// bufsz flag is in MB
		config.Bridge, err = weave.NewPcap(iface, bufSzMB*1024*1024)
		if err != nil {
			Log.Fatal(err)
		}
	}

	if routerName == "" {
		if iface == nil {
			Log.Fatal("Either an interface must be specified with --iface or a name with -name")
		}
		routerName = iface.HardwareAddr.String()
	}

	name, err := weave.PeerNameFromUserInput(routerName)
	if err != nil {
		Log.Fatal(err)
	}

	if nickName == "" {
		nickName, err = os.Hostname()
		if err != nil {
			Log.Fatal(err)
		}
	}

	if password == "" {
		password = os.Getenv("WEAVE_PASSWORD")
	}
	if password == "" {
		Log.Println("Communication between peers is unencrypted.")
	} else {
		config.Password = []byte(password)
		Log.Println("Communication between peers is encrypted.")
	}

	if prof != "" {
		p := *profile.CPUProfile
		p.ProfilePath = prof
		p.NoShutdownHook = true
		defer profile.Start(&p).Stop()
	}

	config.PeerDiscovery = !noDiscovery
	config.Overlay = weave.NewSleeveOverlay(config.Port)

	if pktdebug {
		config.PacketLogging = packetLogging{}
	} else {
		config.PacketLogging = nopPacketLogging{}
	}

	router := weave.NewRouter(config, name, nickName)
	Log.Println("Our name is", router.Ourself)

	var allocator *ipam.Allocator
	var defaultSubnet address.CIDR
	var dockerCli *docker.Client
	if iprangeCIDR != "" {
		allocator, defaultSubnet = createAllocator(router, iprangeCIDR, ipsubnetCIDR, determineQuorum(peerCount, peers))
		dockerCli, err = docker.NewClient(apiPath)
		if err != nil {
			Log.Fatal("Unable to start docker client: ", err)
		}
		if err = dockerCli.AddObserver(allocator); err != nil {
			Log.Fatal("Unable to start watcher", err)
		}
	} else if peerCount > 0 {
		Log.Fatal("--init-peer-count flag specified without --ipalloc-range")
	}

	router.Start()
	if errors := router.ConnectionMaker.InitiateConnections(peers, false); len(errors) > 0 {
		Log.Fatal(errorMessages(errors))
	}

	// The weave script always waits for a status call to succeed,
	// so there is no point in doing "weave launch --http-addr ''".
	// This is here to support stand-alone use of weaver.
	if httpAddr != "" {
		go handleHTTP(router, httpAddr, allocator, defaultSubnet, dockerCli)
	}

	SignalHandlerLoop(router)
}

func errorMessages(errors []error) string {
	var result []string
	for _, err := range errors {
		result = append(result, err.Error())
	}
	return strings.Join(result, "\n")
}

func options() map[string]string {
	options := make(map[string]string)
	mflag.Visit(func(f *mflag.Flag) {
		value := f.Value.String()
		name := canonicalName(f)
		if name == "password" {
			value = "<elided>"
		}
		options[name] = value
	})
	return options
}

func canonicalName(f *mflag.Flag) string {
	for _, n := range f.Names {
		if n[0] != '#' {
			return strings.TrimLeft(n, "#-")
		}
	}
	return ""
}

type packetLogging struct{}

func (packetLogging) LogPacket(msg string, key weave.PacketKey) {
	Log.Println(msg, key.SrcMAC, "->", key.DstMAC)
}

func (packetLogging) LogForwardPacket(msg string, key weave.ForwardPacketKey) {
	Log.Println(msg, key.SrcPeer, key.SrcMAC, "->", key.DstPeer, key.DstMAC)
}

type nopPacketLogging struct{}

func (nopPacketLogging) LogPacket(string, weave.PacketKey) {
}

func (nopPacketLogging) LogForwardPacket(string, weave.ForwardPacketKey) {
}

func parseAndCheckCIDR(cidrStr string) address.CIDR {
	_, cidr, err := address.ParseCIDR(cidrStr)
	if err != nil {
		Log.Fatal(err)
	}
	if cidr.Size() < ipam.MinSubnetSize {
		Log.Fatalf("Allocation range smaller than minimum size %d: %s", ipam.MinSubnetSize, cidrStr)
	}
	return cidr
}

func createAllocator(router *weave.Router, ipRangeStr string, defaultSubnetStr string, quorum uint) (*ipam.Allocator, address.CIDR) {
	ipRange := parseAndCheckCIDR(ipRangeStr)
	defaultSubnet := ipRange
	if defaultSubnetStr != "" {
		defaultSubnet = parseAndCheckCIDR(defaultSubnetStr)
		if !ipRange.Range().Overlaps(defaultSubnet.Range()) {
			Log.Fatalf("Default subnet %s out of bounds: %s", defaultSubnet, ipRange)
		}
	}
	allocator := ipam.NewAllocator(router.Ourself.Peer.Name, router.Ourself.Peer.UID, router.Ourself.Peer.NickName, ipRange.Range(), quorum)

	allocator.SetInterfaces(router.NewGossip("IPallocation", allocator))
	allocator.Start()

	return allocator, defaultSubnet
}

// Pick a quorum size heuristically based on the number of peer
// addresses passed.
func determineQuorum(initPeerCountFlag int, peers []string) uint {
	if initPeerCountFlag > 0 {
		return uint(initPeerCountFlag/2 + 1)
	}

	// Guess a suitable quorum size based on the list of peer
	// addresses.  The peer list might or might not contain an
	// address for this peer, so the conservative assumption is
	// that it doesn't.  The list might contain multiple addresses
	// that resolve to the same peer, in which case the quorum
	// might be larger than it needs to be.  But the user can
	// specify it explicitly if that becomes a problem.
	clusterSize := uint(len(peers) + 1)
	quorum := clusterSize/2 + 1
	Log.Println("Assuming quorum size of", quorum)
	return quorum
}

func handleHTTP(router *weave.Router, httpAddr string, allocator *ipam.Allocator, defaultSubnet address.CIDR, docker *docker.Client) {
	muxRouter := mux.NewRouter()

	if allocator != nil {
		allocator.HandleHTTP(muxRouter, defaultSubnet, docker)
	}

	muxRouter.Methods("GET").Path("/status").Headers("Accept", "application/json").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json, _ := router.StatusJSON(version)
		w.Header().Set("Content-Type", "application/json")
		w.Write(json)
	})

	muxRouter.Methods("GET").Path("/status").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "weave router", version)
		fmt.Fprintln(w, router.Status())
		if allocator != nil {
			fmt.Fprintln(w, allocator.String())
			fmt.Fprintln(w, "Allocator default subnet:", defaultSubnet)
		}
	})

	muxRouter.Methods("POST").Path("/connect").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprint("unable to parse form: ", err), http.StatusBadRequest)
		}
		if errors := router.ConnectionMaker.InitiateConnections(r.Form["peer"], r.FormValue("replace") == "true"); len(errors) > 0 {
			http.Error(w, errorMessages(errors), http.StatusBadRequest)
		}
	})

	muxRouter.Methods("POST").Path("/forget").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprint("unable to parse form: ", err), http.StatusBadRequest)
		}
		router.ConnectionMaker.ForgetConnections(r.Form["peer"])
	})

	http.Handle("/", muxRouter)

	protocol := "tcp"
	if strings.HasPrefix(httpAddr, "/") {
		os.Remove(httpAddr) // in case it's there from last time
		protocol = "unix"
	}
	l, err := net.Listen(protocol, httpAddr)
	if err != nil {
		Log.Fatal("Unable to create http listener socket: ", err)
	}

	err = http.Serve(l, nil)
	if err != nil {
		Log.Fatal("Unable to create http server", err)
	}
}
