// openampd is the OpenAMP policy server for Sequentia: registration,
// policy-checked co-signing of restricted-asset transfers, hosted issuance,
// fee conversion, freezes, clawback, reports, and a transparency log.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/rpc"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/server"
	"github.com/GracedEternalKingCabbageMan/openamp/openampd/internal/store"
)

func main() {
	var (
		listen      = flag.String("listen", "127.0.0.1:8722", "HTTP listen address")
		datadir     = flag.String("datadir", defaultDatadir(), "state directory")
		rpcURL      = flag.String("rpc", "http://127.0.0.1:7041", "elementsd RPC URL")
		rpcAuth     = flag.String("rpcauth", "", "user:pass or cookie:<path>")
		rpcWallet   = flag.String("rpcwallet", "", "wallet name (appended as /wallet/<name>)")
		issuerToken = flag.String("issuertoken", "", "bearer token for issuer endpoints")
		feeAsset    = flag.String("feeasset", "", "display hex of the fee asset the server pays fees in (default: the chain's policy asset)")
		feeSats     = flag.Uint64("feesats", 1000, "flat fee attached to server-funded transactions, in fee-asset atoms")
		demoIssuer  = flag.Bool("demoissuer", false, "hold issuer keys server-side (testnet demo only)")
		electrsURL  = flag.String("electrs", envOr("OPENAMPD_ELECTRS_URL", "http://127.0.0.1:3003"), "explorer (electrs) base URL; prevout fallback when the node lacks -txindex")
		follow      = flag.Duration("follow", 2*time.Second, "chain follower poll interval")
	)
	flag.Parse()

	if *rpcAuth == "" {
		log.Fatal("-rpcauth is required (user:pass or cookie:<path>)")
	}
	node, err := rpc.New(*rpcURL, *rpcAuth)
	if err != nil {
		log.Fatal(err)
	}
	// Scope the wallet client whenever -rpcwallet is passed at all (even ""),
	// so the demo wallet stays addressable once the blinding watch wallet
	// loads alongside it and makes unscoped wallet RPCs ambiguous. An empty
	// name scopes to the node's default wallet via /wallet/.
	walletURL := *rpcURL
	rpcWalletSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "rpcwallet" {
			rpcWalletSet = true
		}
	})
	if rpcWalletSet {
		walletURL = *rpcURL + "/wallet/" + *rpcWallet
	}
	wallet, err := rpc.New(walletURL, *rpcAuth)
	if err != nil {
		log.Fatal(err)
	}

	if *feeAsset == "" {
		var labels map[string]string
		if err := node.Call(&labels, "dumpassetlabels"); err != nil {
			log.Fatalf("dumpassetlabels (set -feeasset explicitly): %v", err)
		}
		*feeAsset = labels["bitcoin"]
		if *feeAsset == "" {
			log.Fatal("could not determine the policy asset; set -feeasset")
		}
	}

	st, err := store.Open(*datadir)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Listen: *listen, IssuerToken: *issuerToken,
		FeeAsset: *feeAsset, FeeSats: *feeSats, DemoIssuer: *demoIssuer,
		ElectrsURL: *electrsURL,
	}, st, node, wallet)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.RunFollower(ctx, *follow)

	log.Printf("openampd listening on %s (fee asset %s, fee %d atoms)", *listen, *feeAsset, *feeSats)
	if err := http.ListenAndServe(*listen, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

func defaultDatadir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".openampd"
	}
	return home + "/.openampd"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
