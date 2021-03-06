// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Copyright (C) 2015-2017 The Lightning Network Developers

package lnd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof" // Blank import to set up profiling HTTP handlers.
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	proxy "github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/headerfs"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"

	"github.com/lightningnetwork/lnd/autopilot"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/cert"
	"github.com/lightningnetwork/lnd/certprovider"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/chanacceptor"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnencrypt"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/btcwallet"
	"github.com/lightningnetwork/lnd/macaroons"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/lightningnetwork/lnd/tor"
	"github.com/lightningnetwork/lnd/walletunlocker"
	"github.com/lightningnetwork/lnd/watchtower"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
)

// WalletUnlockerAuthOptions returns a list of DialOptions that can be used to
// authenticate with the wallet unlocker service.
//
// NOTE: This should only be called after the WalletUnlocker listener has
// signaled it is ready.
func WalletUnlockerAuthOptions(cfg *Config) ([]grpc.DialOption, error) {
	creds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read TLS cert: %v", err)
	}

	// Create a dial options array with the TLS credentials.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	return opts, nil
}

// AdminAuthOptions returns a list of DialOptions that can be used to
// authenticate with the RPC server with admin capabilities.
//
// NOTE: This should only be called after the RPCListener has signaled it is
// ready.
func AdminAuthOptions(cfg *Config) ([]grpc.DialOption, error) {
	creds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("unable to read TLS cert: %v", err)
	}

	// Create a dial options array.
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	// Get the admin macaroon if macaroons are active.
	if !cfg.NoMacaroons {
		// Load the adming macaroon file.
		macBytes, err := ioutil.ReadFile(cfg.AdminMacPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read macaroon "+
				"path (check the network setting!): %v", err)
		}

		mac := &macaroon.Macaroon{}
		if err = mac.UnmarshalBinary(macBytes); err != nil {
			return nil, fmt.Errorf("unable to decode macaroon: %v",
				err)
		}

		// Now we append the macaroon credentials to the dial options.
		cred := macaroons.NewMacaroonCredential(mac)
		opts = append(opts, grpc.WithPerRPCCredentials(cred))
	}

	return opts, nil
}

// GrpcRegistrar is an interface that must be satisfied by an external subserver
// that wants to be able to register its own gRPC server onto lnd's main
// grpc.Server instance.
type GrpcRegistrar interface {
	// RegisterGrpcSubserver is called for each net.Listener on which lnd
	// creates a grpc.Server instance. External subservers implementing this
	// method can then register their own gRPC server structs to the main
	// server instance.
	RegisterGrpcSubserver(*grpc.Server) error
}

// RestRegistrar is an interface that must be satisfied by an external subserver
// that wants to be able to register its own REST mux onto lnd's main
// proxy.ServeMux instance.
type RestRegistrar interface {
	// RegisterRestSubserver is called after lnd creates the main
	// proxy.ServeMux instance. External subservers implementing this method
	// can then register their own REST proxy stubs to the main server
	// instance.
	RegisterRestSubserver(context.Context, *proxy.ServeMux, string,
		[]grpc.DialOption) error
}

// RPCSubserverConfig is a struct that can be used to register an external
// subserver with the custom permissions that map to the gRPC server that is
// going to be registered with the GrpcRegistrar.
type RPCSubserverConfig struct {
	// Registrar is a callback that is invoked for each net.Listener on
	// which lnd creates a grpc.Server instance.
	Registrar GrpcRegistrar

	// Permissions is the permissions required for the external subserver.
	// It is a map between the full HTTP URI of each RPC and its required
	// macaroon permissions. If multiple action/entity tuples are specified
	// per URI, they are all required. See rpcserver.go for a list of valid
	// action and entity values.
	Permissions map[string][]bakery.Op

	// MacaroonValidator is a custom macaroon validator that should be used
	// instead of the default lnd validator. If specified, the custom
	// validator is used for all URIs specified in the above Permissions
	// map.
	MacaroonValidator macaroons.MacaroonValidator
}

// ListenerWithSignal is a net.Listener that has an additional Ready channel that
// will be closed when a server starts listening.
type ListenerWithSignal struct {
	net.Listener

	// Ready will be closed by the server listening on Listener.
	Ready chan struct{}

	// ExternalRPCSubserverCfg is optional and specifies the registration
	// callback and permissions to register external gRPC subservers.
	ExternalRPCSubserverCfg *RPCSubserverConfig

	// ExternalRestRegistrar is optional and specifies the registration
	// callback to register external REST subservers.
	ExternalRestRegistrar RestRegistrar
}

// ListenerCfg is a wrapper around custom listeners that can be passed to lnd
// when calling its main method.
type ListenerCfg struct {
	// WalletUnlocker can be set to the listener to use for the wallet
	// unlocker. If nil a regular network listener will be created.
	WalletUnlocker *ListenerWithSignal

	// RPCListener can be set to the listener to use for the RPC server. If
	// nil a regular network listener will be created.
	RPCListener *ListenerWithSignal
}

// rpcListeners is a function type used for closures that fetches a set of RPC
// listeners for the current configuration. If no custom listeners are present,
// this should return normal listeners from the RPC endpoints defined in the
// config. The second return value us a closure that will close the fetched
// listeners.
type rpcListeners func() ([]*ListenerWithSignal, func(), error)

// Main is the true entry point for lnd. It accepts a fully populated and
// validated main configuration struct and an optional listener config struct.
// This function starts all main system components then blocks until a signal
// is received on the shutdownChan at which point everything is shut down again.
func Main(cfg *Config, lisCfg ListenerCfg, shutdownChan <-chan struct{}) error {
	defer func() {
		ltndLog.Info("Shutdown complete\n")
		err := cfg.LogWriter.Close()
		if err != nil {
			ltndLog.Errorf("Could not close log rotator: %v", err)
		}
	}()

	// Show version at startup.
	ltndLog.Infof("Version: %s commit=%s, build=%s, logging=%s, debuglevel=%s",
		build.Version(), build.Commit, build.Deployment,
		build.LoggingType, cfg.DebugLevel)

	var network string
	switch {
	case cfg.Bitcoin.TestNet3 || cfg.Litecoin.TestNet3:
		network = "testnet"

	case cfg.Bitcoin.MainNet || cfg.Litecoin.MainNet:
		network = "mainnet"

	case cfg.Bitcoin.SimNet || cfg.Litecoin.SimNet:
		network = "simnet"

	case cfg.Bitcoin.RegTest || cfg.Litecoin.RegTest:
		network = "regtest"
	}

	ltndLog.Infof("Active chain: %v (network=%v)",
		strings.Title(cfg.registeredChains.PrimaryChain().String()),
		network,
	)

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			listenAddr := net.JoinHostPort("", cfg.Profile)
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			fmt.Println(http.ListenAndServe(listenAddr, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			err := fmt.Errorf("unable to create CPU profile: %v",
				err)
			ltndLog.Error(err)
			return err
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	localChanDB, remoteChanDB, cleanUp, err := initializeDatabases(ctx, cfg)
	switch {
	case err == channeldb.ErrDryRunMigrationOK:
		ltndLog.Infof("%v, exiting", err)
		return nil
	case err != nil:
		return fmt.Errorf("unable to open databases: %v", err)
	}

	defer cleanUp()

	var serverOpts []grpc.ServerOption
	var restDialOpts []grpc.DialOption
	var restListen func(net.Addr) (net.Listener, error)

	// The real KeyRing isn't available until after the wallet is unlocked,
	// but we need one now. Because we aren't encrypting anything here it can
	// be an empty KeyRing.
	var emptyKeyRing keychain.KeyRing
	// If --tlsencryptkey is set then generate a throwaway TLS pair in memory
	// so we can still have TLS even though the wallet isn't unlocked. These
	// get thrown away for the real certificates once the wallet is unlocked.
	// If TLSEncryptKey is false, then get the TLSConfig like normal.
	if cfg.TLSEncryptKey {
		serverOpts, restDialOpts, restListen, cleanUp, err = getEphemeralTLSConfig(cfg, emptyKeyRing)
	} else {
		serverOpts, restDialOpts, restListen, cleanUp, err = getTLSConfig(cfg, emptyKeyRing)
	}

	if err != nil {
		err := fmt.Errorf("unable to load TLS credentials: %v", err)
		ltndLog.Error(err)
		return err
	}

	defer cleanUp()

	// We use the first RPC listener as the destination for our REST proxy.
	// If the listener is set to listen on all interfaces, we replace it
	// with localhost, as we cannot dial it directly.
	restProxyDest := cfg.RPCListeners[0].String()
	switch {
	case strings.Contains(restProxyDest, "0.0.0.0"):
		restProxyDest = strings.Replace(
			restProxyDest, "0.0.0.0", "127.0.0.1", 1,
		)

	case strings.Contains(restProxyDest, "[::]"):
		restProxyDest = strings.Replace(
			restProxyDest, "[::]", "[::1]", 1,
		)
	}

	// Before starting the wallet, we'll create and start our Neutrino
	// light client instance, if enabled, in order to allow it to sync
	// while the rest of the daemon continues startup.
	mainChain := cfg.Bitcoin
	if cfg.registeredChains.PrimaryChain() == chainreg.LitecoinChain {
		mainChain = cfg.Litecoin
	}
	var neutrinoCS *neutrino.ChainService
	if mainChain.Node == "neutrino" {
		neutrinoBackend, neutrinoCleanUp, err := initNeutrinoBackend(
			cfg, mainChain.ChainDir,
		)
		if err != nil {
			err := fmt.Errorf("unable to initialize neutrino "+
				"backend: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer neutrinoCleanUp()
		neutrinoCS = neutrinoBackend
	}

	var (
		walletInitParams WalletUnlockParams
		shutdownUnlocker = func() {}
		privateWalletPw  = lnwallet.DefaultPrivatePassphrase
		publicWalletPw   = lnwallet.DefaultPublicPassphrase
	)

	// If the user didn't request a seed, then we'll manually assume a
	// wallet birthday of now, as otherwise the seed would've specified
	// this information.
	walletInitParams.Birthday = time.Now()

	// getListeners is a closure that creates listeners from the
	// RPCListeners defined in the config. It also returns a cleanup
	// closure and the server options to use for the GRPC server.
	getListeners := func() ([]*ListenerWithSignal, func(), error) {
		var grpcListeners []*ListenerWithSignal
		for _, grpcEndpoint := range cfg.RPCListeners {
			// Start a gRPC server listening for HTTP/2
			// connections.
			lis, err := lncfg.ListenOnAddress(grpcEndpoint)
			if err != nil {
				ltndLog.Errorf("unable to listen on %s",
					grpcEndpoint)
				return nil, nil, err
			}
			grpcListeners = append(
				grpcListeners, &ListenerWithSignal{
					Listener: lis,
					Ready:    make(chan struct{}),
				})
		}

		cleanup := func() {
			for _, lis := range grpcListeners {
				lis.Close()
			}
		}
		return grpcListeners, cleanup, nil
	}

	// walletUnlockerListeners is a closure we'll hand to the wallet
	// unlocker, that will be called when it needs listeners for its GPRC
	// server.
	walletUnlockerListeners := func() ([]*ListenerWithSignal, func(),
		error) {

		// If we have chosen to start with a dedicated listener for the
		// wallet unlocker, we return it directly.
		if lisCfg.WalletUnlocker != nil {
			return []*ListenerWithSignal{lisCfg.WalletUnlocker},
				func() {}, nil
		}

		// Otherwise we'll return the regular listeners.
		return getListeners()
	}

	// We wait until the user provides a password over RPC. In case lnd is
	// started with the --noseedbackup flag, we use the default password
	// for wallet encryption.
	if !cfg.NoSeedBackup {
		params, shutdown, err := waitForWalletPassword(
			cfg, cfg.RESTListeners, serverOpts, restDialOpts,
			restProxyDest, restListen, walletUnlockerListeners,
		)
		if err != nil {
			err := fmt.Errorf("unable to set up wallet password "+
				"listeners: %v", err)
			ltndLog.Error(err)
			return err
		}

		walletInitParams = *params
		shutdownUnlocker = shutdown
		privateWalletPw = walletInitParams.Password
		publicWalletPw = walletInitParams.Password
		defer func() {
			if err := walletInitParams.UnloadWallet(); err != nil {
				ltndLog.Errorf("Could not unload wallet: %v", err)
			}
		}()

		if walletInitParams.RecoveryWindow > 0 {
			ltndLog.Infof("Wallet recovery mode enabled with "+
				"address lookahead of %d addresses",
				walletInitParams.RecoveryWindow)
		}
	}

	var macaroonService *macaroons.Service
	if !cfg.NoMacaroons {
		// Create the macaroon authentication/authorization service.
		macaroonService, err = macaroons.NewService(
			cfg.networkDir, "lnd", walletInitParams.StatelessInit,
			cfg.DB.Bolt.DBTimeout, macaroons.IPLockChecker,
		)
		if err != nil {
			err := fmt.Errorf("unable to set up macaroon "+
				"authentication: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer macaroonService.Close()

		// Try to unlock the macaroon store with the private password.
		// Ignore ErrAlreadyUnlocked since it could be unlocked by the
		// wallet unlocker.
		err = macaroonService.CreateUnlock(&privateWalletPw)
		if err != nil && err != macaroons.ErrAlreadyUnlocked {
			err := fmt.Errorf("unable to unlock macaroons: %v", err)
			ltndLog.Error(err)
			return err
		}

		// In case we actually needed to unlock the wallet, we now need
		// to create an instance of the admin macaroon and send it to
		// the unlocker so it can forward it to the user. In no seed
		// backup mode, there's nobody listening on the channel and we'd
		// block here forever.
		if !cfg.NoSeedBackup {
			adminMacBytes, err := bakeMacaroon(
				ctx, macaroonService, adminPermissions(),
			)
			if err != nil {
				return err
			}

			// The channel is buffered by one element so writing
			// should not block here.
			walletInitParams.MacResponseChan <- adminMacBytes
		}

		// If the user requested a stateless initialization, no macaroon
		// files should be created.
		if !walletInitParams.StatelessInit &&
			!fileExists(cfg.AdminMacPath) &&
			!fileExists(cfg.ReadMacPath) &&
			!fileExists(cfg.InvoiceMacPath) {

			// Create macaroon files for lncli to use if they don't
			// exist.
			err = genMacaroons(
				ctx, macaroonService, cfg.AdminMacPath,
				cfg.ReadMacPath, cfg.InvoiceMacPath,
			)
			if err != nil {
				err := fmt.Errorf("unable to create macaroons "+
					"%v", err)
				ltndLog.Error(err)
				return err
			}
		}

		// As a security service to the user, if they requested
		// stateless initialization and there are macaroon files on disk
		// we log a warning.
		if walletInitParams.StatelessInit {
			msg := "Found %s macaroon on disk (%s) even though " +
				"--stateless_init was requested. Unencrypted " +
				"state is accessible by the host system. You " +
				"should change the password and use " +
				"--new_mac_root_key with --stateless_init to " +
				"clean up and invalidate old macaroons."

			if fileExists(cfg.AdminMacPath) {
				ltndLog.Warnf(msg, "admin", cfg.AdminMacPath)
			}
			if fileExists(cfg.ReadMacPath) {
				ltndLog.Warnf(msg, "readonly", cfg.ReadMacPath)
			}
			if fileExists(cfg.InvoiceMacPath) {
				ltndLog.Warnf(msg, "invoice", cfg.InvoiceMacPath)
			}
		}
	}

	// Now we're definitely done with the unlocker, shut it down so we can
	// start the main RPC service later.
	shutdownUnlocker()

	// With the information parsed from the configuration, create valid
	// instances of the pertinent interfaces required to operate the
	// Lightning Network Daemon.
	//
	// When we create the chain control, we need storage for the height
	// hints and also the wallet itself, for these two we want them to be
	// replicated, so we'll pass in the remote channel DB instance.
	chainControlCfg := &chainreg.Config{
		Bitcoin:                     cfg.Bitcoin,
		Litecoin:                    cfg.Litecoin,
		PrimaryChain:                cfg.registeredChains.PrimaryChain,
		HeightHintCacheQueryDisable: cfg.HeightHintCacheQueryDisable,
		NeutrinoMode:                cfg.NeutrinoMode,
		BitcoindMode:                cfg.BitcoindMode,
		LitecoindMode:               cfg.LitecoindMode,
		BtcdMode:                    cfg.BtcdMode,
		LtcdMode:                    cfg.LtcdMode,
		LocalChanDB:                 localChanDB,
		RemoteChanDB:                remoteChanDB,
		PrivateWalletPw:             privateWalletPw,
		PublicWalletPw:              publicWalletPw,
		Birthday:                    walletInitParams.Birthday,
		RecoveryWindow:              walletInitParams.RecoveryWindow,
		Wallet:                      walletInitParams.Wallet,
		DBTimeOut:                   cfg.DB.Bolt.DBTimeout,
		NeutrinoCS:                  neutrinoCS,
		ActiveNetParams:             cfg.ActiveNetParams,
		FeeURL:                      cfg.FeeURL,
	}

	activeChainControl, err := chainreg.NewChainControl(chainControlCfg)
	if err != nil {
		err := fmt.Errorf("unable to create chain control: %v", err)
		ltndLog.Error(err)
		return err
	}

	// Finally before we start the server, we'll register the "holy
	// trinity" of interface for our current "home chain" with the active
	// chainRegistry interface.
	primaryChain := cfg.registeredChains.PrimaryChain()
	cfg.registeredChains.RegisterChain(primaryChain, activeChainControl)

	// TODO(roasbeef): add rotation
	idKeyDesc, err := activeChainControl.KeyRing.DeriveKey(
		keychain.KeyLocator{
			Family: keychain.KeyFamilyNodeKey,
			Index:  0,
		},
	)
	if err != nil {
		err := fmt.Errorf("error deriving node key: %v", err)
		ltndLog.Error(err)
		return err
	}

	if cfg.Tor.Active {
		srvrLog.Infof("Proxying all network traffic via Tor "+
			"(stream_isolation=%v)! NOTE: Ensure the backend node "+
			"is proxying over Tor as well", cfg.Tor.StreamIsolation)
	}

	// If the watchtower client should be active, open the client database.
	// This is done here so that Close always executes when lndMain returns.
	var towerClientDB *wtdb.ClientDB
	if cfg.WtClient.Active {
		var err error
		towerClientDB, err = wtdb.OpenClientDB(
			cfg.localDatabaseDir(), cfg.DB.Bolt.DBTimeout,
		)
		if err != nil {
			err := fmt.Errorf("unable to open watchtower client "+
				"database: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer towerClientDB.Close()
	}

	// If tor is active and either v2 or v3 onion services have been specified,
	// make a tor controller and pass it into both the watchtower server and
	// the regular lnd server.
	var torController *tor.Controller
	if cfg.Tor.Active && (cfg.Tor.V2 || cfg.Tor.V3) {
		torController = tor.NewController(
			cfg.Tor.Control, cfg.Tor.TargetIPAddress, cfg.Tor.Password,
		)

		// Start the tor controller before giving it to any other subsystems.
		if err := torController.Start(); err != nil {
			err := fmt.Errorf("unable to initialize tor controller: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer func() {
			if err := torController.Stop(); err != nil {
				ltndLog.Errorf("error stopping tor controller: %v", err)
			}
		}()
	}

	var tower *watchtower.Standalone
	if cfg.Watchtower.Active {
		// Segment the watchtower directory by chain and network.
		towerDBDir := filepath.Join(
			cfg.Watchtower.TowerDir,
			cfg.registeredChains.PrimaryChain().String(),
			lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
		)

		towerDB, err := wtdb.OpenTowerDB(
			towerDBDir, cfg.DB.Bolt.DBTimeout,
		)
		if err != nil {
			err := fmt.Errorf("unable to open watchtower "+
				"database: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer towerDB.Close()

		towerKeyDesc, err := activeChainControl.KeyRing.DeriveKey(
			keychain.KeyLocator{
				Family: keychain.KeyFamilyTowerID,
				Index:  0,
			},
		)
		if err != nil {
			err := fmt.Errorf("error deriving tower key: %v", err)
			ltndLog.Error(err)
			return err
		}

		wtCfg := &watchtower.Config{
			BlockFetcher:   activeChainControl.ChainIO,
			DB:             towerDB,
			EpochRegistrar: activeChainControl.ChainNotifier,
			Net:            cfg.net,
			NewAddress: func() (btcutil.Address, error) {
				return activeChainControl.Wallet.NewAddress(
					lnwallet.WitnessPubKey, false,
				)
			},
			NodeKeyECDH: keychain.NewPubKeyECDH(
				towerKeyDesc, activeChainControl.KeyRing,
			),
			PublishTx: activeChainControl.Wallet.PublishTransaction,
			ChainHash: *cfg.ActiveNetParams.GenesisHash,
		}

		// If there is a tor controller (user wants auto hidden services), then
		// store a pointer in the watchtower config.
		if torController != nil {
			wtCfg.TorController = torController
			wtCfg.WatchtowerKeyPath = cfg.Tor.WatchtowerKeyPath
			wtCfg.EncryptKey = cfg.Tor.EncryptKey
			wtCfg.KeyRing = activeChainControl.KeyRing

			switch {
			case cfg.Tor.V2:
				wtCfg.Type = tor.V2
			case cfg.Tor.V3:
				wtCfg.Type = tor.V3
			}
		}

		wtConfig, err := cfg.Watchtower.Apply(wtCfg, lncfg.NormalizeAddresses)
		if err != nil {
			err := fmt.Errorf("unable to configure watchtower: %v",
				err)
			ltndLog.Error(err)
			return err
		}

		tower, err = watchtower.New(wtConfig)
		if err != nil {
			err := fmt.Errorf("unable to create watchtower: %v", err)
			ltndLog.Error(err)
			return err
		}
	}

	// Initialize the ChainedAcceptor.
	chainedAcceptor := chanacceptor.NewChainedAcceptor()

	// Set up the core server which will listen for incoming peer
	// connections.
	server, err := newServer(
		cfg, cfg.Listeners, localChanDB, remoteChanDB, towerClientDB,
		activeChainControl, &idKeyDesc, walletInitParams.ChansToRestore,
		chainedAcceptor, torController,
	)
	if err != nil {
		err := fmt.Errorf("unable to create server: %v", err)
		ltndLog.Error(err)
		return err
	}

	// Set up an autopilot manager from the current config. This will be
	// used to manage the underlying autopilot agent, starting and stopping
	// it at will.
	atplCfg, err := initAutoPilot(server, cfg.Autopilot, mainChain, cfg.ActiveNetParams)
	if err != nil {
		err := fmt.Errorf("unable to initialize autopilot: %v", err)
		ltndLog.Error(err)
		return err
	}

	atplManager, err := autopilot.NewManager(atplCfg)
	if err != nil {
		err := fmt.Errorf("unable to create autopilot manager: %v", err)
		ltndLog.Error(err)
		return err
	}
	if err := atplManager.Start(); err != nil {
		err := fmt.Errorf("unable to start autopilot manager: %v", err)
		ltndLog.Error(err)
		return err
	}
	defer atplManager.Stop()

	// If --tlsencryptkey is set, we previously generated a throwaway TLSConfig
	// Now we want to remove that and load the persistent TLSConfig
	// The wallet is unlocked at this point so we can use the real KeyRing
	if cfg.TLSEncryptKey {
		tmpCertPath := cfg.TLSCertPath + ".tmp"
		tmpExternalCertPath := fmt.Sprintf("%s/%s/tls.cert.tmp", cfg.LndDir, cfg.ExternalSSLProvider)
		err = os.Remove(tmpCertPath)
		if err != nil {
			ltndLog.Warn("unable to delete temp cert at %v", tmpCertPath)
		}
		err = os.Remove(tmpExternalCertPath)
		if err != nil {
			ltndLog.Warn("unable to delete temp external cert at %v", tmpExternalCertPath)
		}
		serverOpts, restDialOpts, restListen, _, err = getTLSConfig(cfg, activeChainControl.KeyRing)
		if err != nil {
			err := fmt.Errorf("unable to load TLS credentials: %v", err)
			ltndLog.Error(err)
			return err
		}
	}

	// rpcListeners is a closure we'll hand to the rpc server, that will be
	// called when it needs listeners for its GPRC server.
	rpcListeners := func() ([]*ListenerWithSignal, func(), error) {
		// If we have chosen to start with a dedicated listener for the
		// rpc server, we return it directly.
		if lisCfg.RPCListener != nil {
			return []*ListenerWithSignal{lisCfg.RPCListener},
				func() {}, nil
		}

		// Otherwise we'll return the regular listeners.
		return getListeners()
	}

	// Initialize, and register our implementation of the gRPC interface
	// exported by the rpcServer.
	rpcServer, err := newRPCServer(
		cfg, server, macaroonService, cfg.SubRPCServers, serverOpts,
		restDialOpts, restProxyDest, atplManager, server.invoices,
		tower, restListen, rpcListeners, chainedAcceptor,
	)
	if err != nil {
		err := fmt.Errorf("unable to create RPC server: %v", err)
		ltndLog.Error(err)
		return err
	}
	if err := rpcServer.Start(); err != nil {
		err := fmt.Errorf("unable to start RPC server: %v", err)
		ltndLog.Error(err)
		return err
	}
	defer rpcServer.Stop()

	// If we're not in regtest or simnet mode, We'll wait until we're fully
	// synced to continue the start up of the remainder of the daemon. This
	// ensures that we don't accept any possibly invalid state transitions, or
	// accept channels with spent funds.
	if !(cfg.Bitcoin.RegTest || cfg.Bitcoin.SimNet ||
		cfg.Litecoin.RegTest || cfg.Litecoin.SimNet) {

		_, bestHeight, err := activeChainControl.ChainIO.GetBestBlock()
		if err != nil {
			err := fmt.Errorf("unable to determine chain tip: %v",
				err)
			ltndLog.Error(err)
			return err
		}

		ltndLog.Infof("Waiting for chain backend to finish sync, "+
			"start_height=%v", bestHeight)

		for {
			if !signal.Alive() {
				return nil
			}

			synced, _, err := activeChainControl.Wallet.IsSynced()
			if err != nil {
				err := fmt.Errorf("unable to determine if "+
					"wallet is synced: %v", err)
				ltndLog.Error(err)
				return err
			}

			if synced {
				break
			}

			time.Sleep(time.Second * 1)
		}

		_, bestHeight, err = activeChainControl.ChainIO.GetBestBlock()
		if err != nil {
			err := fmt.Errorf("unable to determine chain tip: %v",
				err)
			ltndLog.Error(err)
			return err
		}

		ltndLog.Infof("Chain backend is fully synced (end_height=%v)!",
			bestHeight)
	}

	// With all the relevant chains initialized, we can finally start the
	// server itself.
	if err := server.Start(); err != nil {
		err := fmt.Errorf("unable to start server: %v", err)
		ltndLog.Error(err)
		return err
	}
	defer server.Stop()

	// Now that the server has started, if the autopilot mode is currently
	// active, then we'll start the autopilot agent immediately. It will be
	// stopped together with the autopilot service.
	if cfg.Autopilot.Active {
		if err := atplManager.StartAgent(); err != nil {
			err := fmt.Errorf("unable to start autopilot agent: %v",
				err)
			ltndLog.Error(err)
			return err
		}
	}

	if cfg.Watchtower.Active {
		if err := tower.Start(); err != nil {
			err := fmt.Errorf("unable to start watchtower: %v", err)
			ltndLog.Error(err)
			return err
		}
		defer tower.Stop()
	}

	// Wait for shutdown signal from either a graceful server stop or from
	// the interrupt handler.
	<-shutdownChan
	return nil
}

// createExternalCert creates an Externally provisioned SSL Certificate
func createExternalCert(cfg *Config, keyBytes []byte, certLocation string) (returnCert tls.Certificate, err error) {
	var certServer *http.Server

	switch cfg.ExternalSSLProvider {
	case "zerossl":
		return createExternalCertZeroSsl(cfg, keyBytes, certLocation, certServer)
	case "apiservice":
		return createExternalCertApiService(cfg, keyBytes, certLocation)
	default:
		return returnCert, fmt.Errorf("unknown external certificate provider: %s", cfg.ExternalSSLProvider)
	}
}

func createExternalCertZeroSsl(cfg *Config, keyBytes []byte,
	certLocation string, certServer *http.Server) (returnCert tls.Certificate, err error) {

	csr, err := certprovider.ZeroSSLGenerateCsr(keyBytes, cfg.ExternalSSLDomain)
	if err != nil {
		return returnCert, err
	}

	rpcsLog.Debugf("created csr for %s", cfg.ExternalSSLDomain)
	externalCert, err := certprovider.ZeroSSLRequestCert(csr, cfg.ExternalSSLDomain)
	if err != nil {
		return returnCert, err
	}

	rpcsLog.Infof("received cert request with id %s", externalCert.Id)
	domain := externalCert.CommonName
	path := externalCert.Validation.OtherValidation[domain].FileValidationUrlHttp
	path = strings.Replace(path, "http://"+domain, "", -1)

	content := strings.Join(externalCert.Validation.OtherValidation[domain].FileValidationContent[:], "\n")

	go func() {
		addr := fmt.Sprintf(":%v", cfg.ExternalSSLPort)
		http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(content))
		})
		certServer = &http.Server{
			Addr:    addr,
			Handler: http.DefaultServeMux,
		}
		rpcsLog.Infof("starting certificate validator server at %s",
			addr)
		err := certServer.ListenAndServe()
		if err != nil {
			rpcsLog.Errorf("there was a problem starting external cert validation server: %v",
				err)
			return
		}
	}()

	err = certprovider.ZeroSSLValidateCert(externalCert)
	if err != nil {
		return returnCert, err
	}

	rpcsLog.Debug("requested certificate to be validated")
	checkCount := 0
	retries := 0
	for {
		newCert, err := certprovider.ZeroSSLGetCert(externalCert)
		if err != nil {
			return returnCert, err
		}
		status := newCert.Status
		rpcsLog.Debugf("found certificate in state %s", status)
		if status == "issued" {
			rpcsLog.Infof("found certificate in state %s", status)
			break
		} else if status == "draft" {
			err = certprovider.ZeroSSLValidateCert(externalCert)
			if err != nil {
				return returnCert, err
			}
		}
		if retries > 3 {
			rpcsLog.Error("Still can't get a certificate after 3 retries. Failing...")
			return returnCert, fmt.Errorf("Timed out trying to create SSL Certificate")
		}
		if checkCount > 15 {
			rpcsLog.Warn("Timed out waiting for cert. Requesting a new one.")
			externalCert, err = certprovider.ZeroSSLRequestCert(csr, cfg.ExternalSSLDomain)
			if err != nil {
				return returnCert, err
			}
			rpcsLog.Infof("received cert request with id %s", externalCert.Id)
			retries += 1
			checkCount = 0
		}
		checkCount += 1
		time.Sleep(2 * time.Second)
	}

	certificate, caBundle, err := certprovider.ZeroSSLDownloadCert(externalCert)
	if err != nil {
		return returnCert, err
	}

	externalCertData, err := writeExternalCert(certificate, caBundle, keyBytes, certLocation)
	if err != nil {
		return returnCert, err
	}

	rpcsLog.Info("shutting down certificate validator server")
	certServer.Close()

	return externalCertData, nil
}

func createExternalCertApiService(cfg *Config, keyBytes []byte,
	certLocation string) (returnCert tls.Certificate, err error) {

	existingCert, err := certprovider.ApiServiceGetCertificate(cfg.ExternalSSLDomain)
	if err == nil {
		certificate := existingCert.Certificate
		caBundle := existingCert.OriginCa

		return writeExternalCert(certificate, caBundle, keyBytes, certLocation)
	}

	csr, err := certprovider.GenerateCsr(keyBytes, cfg.ExternalSSLDomain)
	if err != nil {
		return returnCert, err
	}

	rpcsLog.Debugf("created csr for %s", cfg.ExternalSSLDomain)

	externalCert, err := certprovider.ApiServiceRequestCertificate(csr, cfg.ExternalSSLDomain)
	if err != nil {
		return returnCert, err
	}

	certificate := externalCert.Certificate
	caBundle := externalCert.OriginCa

	return writeExternalCert(certificate, caBundle, keyBytes, certLocation)
}

func writeExternalCert(certificate string, caBundle string,
	keyBytes []byte, certLocation string) (returnCert tls.Certificate, err error) {

	externalCertBytes := []byte(certificate + "\n" + caBundle)
	if err = ioutil.WriteFile(certLocation, externalCertBytes, 0644); err != nil {
		return returnCert, err
	}

	rpcsLog.Infof("successfully wrote external SSL certificate to %s",
		certLocation)

	externalCertData, _, err := cert.LoadCert(
		externalCertBytes, keyBytes,
	)

	if err != nil {
		return returnCert, err
	}

	return externalCertData, nil
}

// getEphemeralTLSConfig returns a temporary TLS configuration with the TLS
// key and cert for the gRPC server and credentials and a proxy destination
// for the REST reverse proxy. The key is not written to disk.
func getEphemeralTLSConfig(cfg *Config, keyRing keychain.KeyRing) (
	[]grpc.ServerOption, []grpc.DialOption,
	func(net.Addr) (net.Listener, error), func(), error) {

	rpcsLog.Infof("Generating ephemeral TLS certificates...")
	tmpValidity := 24 * time.Hour
	// Append .tmp to the end of the cert for differentiation.
	tmpCertPath := cfg.TLSCertPath + ".tmp"
	var externalSSLCertPath string
	keyType := "ec"
	if cfg.ExternalSSLProvider != "" {
		keyType = "rsa"
		externalSSLCertPath = fmt.Sprintf("%s/%s/tls.cert.tmp", cfg.LndDir, cfg.ExternalSSLProvider)
	}

	// Pass in blank string for the key path so the
	// function doesn't write them to disk.
	certBytes, keyBytes, err := cert.GenCertPair(
		"lnd temporary autogenerated cert", tmpCertPath,
		"", cfg.TLSExtraIPs, cfg.TLSExtraDomains,
		cfg.TLSDisableAutofill, tmpValidity, false, keyRing, keyType,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var externalCertData tls.Certificate
	if cfg.ExternalSSLProvider != "" {
		externalCertData, err = createExternalCert(
			cfg, keyBytes, externalSSLCertPath,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	rpcsLog.Infof("Done generating ephemeral TLS certificates")

	certData, parsedCert, err := cert.LoadCert(
		certBytes, keyBytes,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	certList := []tls.Certificate{certData}
	if cfg.ExternalSSLProvider != "" {
		certList = append(certList, externalCertData)
	}

	tlsCfg := cert.TLSConfFromCert(certList)
	certPool := x509.NewCertPool()
	certPool.AddCert(parsedCert)
	restCreds := credentials.NewClientTLSFromCert(certPool, "")

	cleanUp := func() {}
	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	// For our REST dial options, we'll still use TLS, but also increase
	// the max message size that we'll decode to allow clients to hit
	// endpoints which return more data such as the DescribeGraph call.
	// We set this to 200MiB atm. Should be the same value as maxMsgRecvSize
	// in cmd/lncli/main.go.
	restDialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(restCreds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200),
		),
	}

	// Return a function closure that can be used to listen on a given
	// address with the current TLS config.
	restListen := func(addr net.Addr) (net.Listener, error) {
		// For restListen we will call ListenOnAddress if TLS is
		// disabled.
		if cfg.DisableRestTLS {
			return lncfg.ListenOnAddress(addr)
		}

		return lncfg.TLSListenOnAddress(addr, tlsCfg)
	}

	return serverOpts, restDialOpts, restListen, cleanUp, nil
}

// getTLSConfig returns a TLS configuration for the gRPC server and credentials
// and a proxy destination for the REST reverse proxy. The cert and key are
// written to disk and the private key can be optionally encrypted.
func getTLSConfig(cfg *Config, keyRing keychain.KeyRing) (
	[]grpc.ServerOption, []grpc.DialOption,
	func(net.Addr) (net.Listener, error), func(), error) {

	var (
		keyType          string
		privateKeyPrefix []byte
	)

	switch cfg.ExternalSSLProvider {
	case "":
		keyType = "ec"
		privateKeyPrefix = []byte("-----BEGIN EC PRIVATE KEY-----")
	default:
		keyType = "rsa"
		privateKeyPrefix = []byte("-----BEGIN RSA PRIVATE KEY-----")
	}

	externalSSLCertPath := fmt.Sprintf("%s/%s/tls.cert", cfg.LndDir, cfg.ExternalSSLProvider)

	// Ensure we create TLS key and certificate if they don't exist.
	if !fileExists(cfg.TLSCertPath) && !fileExists(cfg.TLSKeyPath) {
		rpcsLog.Infof("Generating TLS certificates...")
		_, _, err := cert.GenCertPair(
			"lnd autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cert.DefaultAutogenValidity,
			cfg.TLSEncryptKey, keyRing, keyType,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		// If the external ssl provider is supplied and there was a key rotation
		// then we need to rotate the external SSL too. Just delete here so it
		// can be regenerated a little farther down
		if cfg.ExternalSSLProvider != "" {
			os.Remove(externalSSLCertPath)
		}

		rpcsLog.Infof("Done generating TLS certificates")
	}

	certBytes, err := ioutil.ReadFile(cfg.TLSCertPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyBytes, err := ioutil.ReadFile(cfg.TLSKeyPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Do a check to see if the TLS private key is encrypted. If it's encrypted,
	// try to decrypt it. If it's in plaintext but should be encrypted,
	// then encrypt it.
	if !bytes.HasPrefix(keyBytes, privateKeyPrefix) {
		// If the private key is encrypted but the user didn't pass
		// --tlsencryptkey we error out. This is because the wallet is not
		// unlocked yet and we don't have access to the keys yet for decrypt.
		if !cfg.TLSEncryptKey {
			return nil, nil, nil, nil, fmt.Errorf("it appears the TLS key is " +
				"encrypted but you didn't pass the --tlsencryptkey flag. " +
				"Please restart lnd with the --tlsencryptkey flag or delete " +
				"the TLS files for regeneration")
		}
		reader := bytes.NewReader(keyBytes)
		keyBytes, err = lnencrypt.DecryptPayloadFromReader(reader, keyRing)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else if cfg.TLSEncryptKey {
		// If the user requests an encrypted key but the key is in plaintext
		// we encrypt the key before writing to disk.
		keyBuf := bytes.NewBuffer(keyBytes)
		var b bytes.Buffer
		err = lnencrypt.EncryptPayloadToWriter(*keyBuf, &b, keyRing)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if err = ioutil.WriteFile(cfg.TLSKeyPath, b.Bytes(), 0600); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	var externalCertData tls.Certificate
	if cfg.ExternalSSLProvider != "" {
		// Ensure we create external TLS certificate if they don't exist.
		if !fileExists(externalSSLCertPath) {
			ltndLog.Infof("Requesting external certificate for domain %v",
				cfg.ExternalSSLDomain)
			_, err = createExternalCert(
				cfg, keyBytes, externalSSLCertPath,
			)
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}
		externalCertBytes, err := ioutil.ReadFile(externalSSLCertPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		externalCertData, _, err = cert.LoadCert(
			externalCertBytes, keyBytes,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	certData, parsedCert, err := cert.LoadCert(
		certBytes, keyBytes,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// We check whether the certifcate we have on disk match the IPs and
	// domains specified by the config. If the extra IPs or domains have
	// changed from when the certificate was created, we will refresh the
	// certificate if auto refresh is active.
	refresh := false
	if cfg.TLSAutoRefresh {
		refresh, err = cert.IsOutdated(
			parsedCert, cfg.TLSExtraIPs,
			cfg.TLSExtraDomains, cfg.TLSDisableAutofill,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	// If the certificate expired or it was outdated, delete it and the TLS
	// key and generate a new pair.
	if time.Now().After(parsedCert.NotAfter) || refresh {
		ltndLog.Info("TLS certificate is expired or outdated, " +
			"generating a new one")

		err := os.Remove(cfg.TLSCertPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		err = os.Remove(cfg.TLSKeyPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if cfg.ExternalSSLProvider != "" {
			err = os.Remove(externalSSLCertPath)
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}

		rpcsLog.Infof("Renewing TLS certificates...")
		_, _, err = cert.GenCertPair(
			"lnd autogenerated cert", cfg.TLSCertPath,
			cfg.TLSKeyPath, cfg.TLSExtraIPs, cfg.TLSExtraDomains,
			cfg.TLSDisableAutofill, cert.DefaultAutogenValidity,
			cfg.TLSEncryptKey, keyRing, keyType,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		rpcsLog.Infof("Done renewing TLS certificates")

		// Reload the certificate data.
		certBytes, err := ioutil.ReadFile(cfg.TLSCertPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		keyBytes, err := ioutil.ReadFile(cfg.TLSKeyPath)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		if cfg.ExternalSSLProvider != "" {
			// Ensure we create external TLS certificate if they don't exist.
			if !fileExists(externalSSLCertPath) {
				ltndLog.Infof("Requesting external certificate for domain %v",
					cfg.ExternalSSLDomain)
				_, err = createExternalCert(
					cfg, keyBytes, externalSSLCertPath,
				)
				if err != nil {
					return nil, nil, nil, nil, err
				}
			}
			externalCertBytes, err := ioutil.ReadFile(externalSSLCertPath)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			externalCertData, _, err = cert.LoadCert(
				externalCertBytes, keyBytes,
			)
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}

		// If key encryption is set, then decrypt the file.
		// We don't need to do a file type check here because GenCertPair
		// has been ran with the same value for cfg.TLSEncryptKey.
		if cfg.TLSEncryptKey {
			reader := bytes.NewReader(keyBytes)
			keyBytes, err = lnencrypt.DecryptPayloadFromReader(reader, keyRing)
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}

		certData, _, err = cert.LoadCert(
			certBytes, keyBytes,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	certList := []tls.Certificate{certData}
	if cfg.ExternalSSLProvider != "" {
		certList = append(certList, externalCertData)
	}
	tlsCfg := cert.TLSConfFromCert(certList)
	restCreds, err := credentials.NewClientTLSFromFile(cfg.TLSCertPath, "")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// If Let's Encrypt is enabled, instantiate autocert to request/renew
	// the certificates.
	cleanUp := func() {}
	if cfg.LetsEncryptDomain != "" {
		ltndLog.Infof("Using Let's Encrypt certificate for domain %v",
			cfg.LetsEncryptDomain)

		manager := autocert.Manager{
			Cache:      autocert.DirCache(cfg.LetsEncryptDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.LetsEncryptDomain),
		}

		srv := &http.Server{
			Addr:    cfg.LetsEncryptListen,
			Handler: manager.HTTPHandler(nil),
		}
		shutdownCompleted := make(chan struct{})
		cleanUp = func() {
			err := srv.Shutdown(context.Background())
			if err != nil {
				ltndLog.Errorf("Autocert listener shutdown "+
					" error: %v", err)

				return
			}
			<-shutdownCompleted
			ltndLog.Infof("Autocert challenge listener stopped")
		}

		go func() {
			ltndLog.Infof("Autocert challenge listener started "+
				"at %v", cfg.LetsEncryptListen)

			err := srv.ListenAndServe()
			if err != http.ErrServerClosed {
				ltndLog.Errorf("autocert http: %v", err)
			}
			close(shutdownCompleted)
		}()

		getCertificate := func(h *tls.ClientHelloInfo) (
			*tls.Certificate, error) {

			lecert, err := manager.GetCertificate(h)
			if err != nil {
				ltndLog.Errorf("GetCertificate: %v", err)
				return &certData, nil
			}

			return lecert, err
		}

		// The self-signed tls.cert remains available as fallback.
		tlsCfg.GetCertificate = getCertificate
	}

	serverCreds := credentials.NewTLS(tlsCfg)
	serverOpts := []grpc.ServerOption{grpc.Creds(serverCreds)}

	// For our REST dial options, we'll still use TLS, but also increase
	// the max message size that we'll decode to allow clients to hit
	// endpoints which return more data such as the DescribeGraph call.
	// We set this to 200MiB atm. Should be the same value as maxMsgRecvSize
	// in cmd/lncli/main.go.
	restDialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(restCreds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1 * 1024 * 1024 * 200),
		),
	}

	// Return a function closure that can be used to listen on a given
	// address with the current TLS config.
	restListen := func(addr net.Addr) (net.Listener, error) {
		// For restListen we will call ListenOnAddress if TLS is
		// disabled.
		if cfg.DisableRestTLS {
			return lncfg.ListenOnAddress(addr)
		}

		return lncfg.TLSListenOnAddress(addr, tlsCfg)
	}

	return serverOpts, restDialOpts, restListen, cleanUp, nil
}

// fileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/btcsuite/btcd
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// bakeMacaroon creates a new macaroon with newest version and the given
// permissions then returns it binary serialized.
func bakeMacaroon(ctx context.Context, svc *macaroons.Service,
	permissions []bakery.Op) ([]byte, error) {

	mac, err := svc.NewMacaroon(
		ctx, macaroons.DefaultRootKeyID, permissions...,
	)
	if err != nil {
		return nil, err
	}

	return mac.M().MarshalBinary()
}

// genMacaroons generates three macaroon files; one admin-level, one for
// invoice access and one read-only. These can also be used to generate more
// granular macaroons.
func genMacaroons(ctx context.Context, svc *macaroons.Service,
	admFile, roFile, invoiceFile string) error {

	// First, we'll generate a macaroon that only allows the caller to
	// access invoice related calls. This is useful for merchants and other
	// services to allow an isolated instance that can only query and
	// modify invoices.
	invoiceMacBytes, err := bakeMacaroon(ctx, svc, invoicePermissions)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(invoiceFile, invoiceMacBytes, 0644)
	if err != nil {
		_ = os.Remove(invoiceFile)
		return err
	}

	// Generate the read-only macaroon and write it to a file.
	roBytes, err := bakeMacaroon(ctx, svc, readPermissions)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(roFile, roBytes, 0644); err != nil {
		_ = os.Remove(roFile)
		return err
	}

	// Generate the admin macaroon and write it to a file.
	admBytes, err := bakeMacaroon(ctx, svc, adminPermissions())
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(admFile, admBytes, 0600); err != nil {
		_ = os.Remove(admFile)
		return err
	}

	return nil
}

// adminPermissions returns a list of all permissions in a safe way that doesn't
// modify any of the source lists.
func adminPermissions() []bakery.Op {
	admin := make([]bakery.Op, len(readPermissions)+len(writePermissions))
	copy(admin[:len(readPermissions)], readPermissions)
	copy(admin[len(readPermissions):], writePermissions)
	return admin
}

// WalletUnlockParams holds the variables used to parameterize the unlocking of
// lnd's wallet after it has already been created.
type WalletUnlockParams struct {
	// Password is the public and private wallet passphrase.
	Password []byte

	// Birthday specifies the approximate time that this wallet was created.
	// This is used to bound any rescans on startup.
	Birthday time.Time

	// RecoveryWindow specifies the address lookahead when entering recovery
	// mode. A recovery will be attempted if this value is non-zero.
	RecoveryWindow uint32

	// Wallet is the loaded and unlocked Wallet. This is returned
	// from the unlocker service to avoid it being unlocked twice (once in
	// the unlocker service to check if the password is correct and again
	// later when lnd actually uses it). Because unlocking involves scrypt
	// which is resource intensive, we want to avoid doing it twice.
	Wallet *wallet.Wallet

	// ChansToRestore a set of static channel backups that should be
	// restored before the main server instance starts up.
	ChansToRestore walletunlocker.ChannelsToRecover

	// UnloadWallet is a function for unloading the wallet, which should
	// be called on shutdown.
	UnloadWallet func() error

	// StatelessInit signals that the user requested the daemon to be
	// initialized stateless, which means no unencrypted macaroons should be
	// written to disk.
	StatelessInit bool

	// MacResponseChan is the channel for sending back the admin macaroon to
	// the WalletUnlocker service.
	MacResponseChan chan []byte
}

// waitForWalletPassword will spin up gRPC and REST endpoints for the
// WalletUnlocker server, and block until a password is provided by
// the user to this RPC server.
func waitForWalletPassword(cfg *Config, restEndpoints []net.Addr,
	serverOpts []grpc.ServerOption, restDialOpts []grpc.DialOption,
	restProxyDest string, restListen func(net.Addr) (net.Listener, error),
	getListeners rpcListeners) (*WalletUnlockParams, func(), error) {

	chainConfig := cfg.Bitcoin
	if cfg.registeredChains.PrimaryChain() == chainreg.LitecoinChain {
		chainConfig = cfg.Litecoin
	}

	// The macaroonFiles are passed to the wallet unlocker so they can be
	// deleted and recreated in case the root macaroon key is also changed
	// during the change password operation.
	macaroonFiles := []string{
		cfg.AdminMacPath, cfg.ReadMacPath, cfg.InvoiceMacPath,
	}
	pwService := walletunlocker.New(
		chainConfig.ChainDir, cfg.ActiveNetParams.Params,
		!cfg.SyncFreelist, macaroonFiles, cfg.DB.Bolt.DBTimeout,
		cfg.ResetWalletTransactions,
	)

	// Set up a new PasswordService, which will listen for passwords
	// provided over RPC.
	grpcServer := grpc.NewServer(serverOpts...)
	lnrpc.RegisterWalletUnlockerServer(grpcServer, pwService)

	var shutdownFuncs []func()
	shutdown := func() {
		// Make sure nothing blocks on reading on the macaroon channel,
		// otherwise the GracefulStop below will never return.
		close(pwService.MacResponseChan)

		for _, shutdownFn := range shutdownFuncs {
			shutdownFn()
		}
	}
	shutdownFuncs = append(shutdownFuncs, grpcServer.GracefulStop)

	// Start a gRPC server listening for HTTP/2 connections, solely used
	// for getting the encryption password from the client.
	listeners, cleanup, err := getListeners()
	if err != nil {
		return nil, shutdown, err
	}
	shutdownFuncs = append(shutdownFuncs, cleanup)

	// Use a WaitGroup so we can be sure the instructions on how to input the
	// password is the last thing to be printed to the console.
	var wg sync.WaitGroup

	for _, lis := range listeners {
		wg.Add(1)
		go func(lis *ListenerWithSignal) {
			rpcsLog.Infof("Password RPC server listening on %s",
				lis.Addr())

			// Close the ready chan to indicate we are listening.
			close(lis.Ready)

			wg.Done()
			_ = grpcServer.Serve(lis)
		}(lis)
	}

	// Start a REST proxy for our gRPC server above.
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	shutdownFuncs = append(shutdownFuncs, cancel)

	mux := proxy.NewServeMux()

	err = lnrpc.RegisterWalletUnlockerHandlerFromEndpoint(
		ctx, mux, restProxyDest, restDialOpts,
	)
	if err != nil {
		return nil, shutdown, err
	}

	srv := &http.Server{Handler: allowCORS(mux, cfg.RestCORS)}

	for _, restEndpoint := range restEndpoints {
		lis, err := restListen(restEndpoint)
		if err != nil {
			ltndLog.Errorf("Password gRPC proxy unable to listen "+
				"on %s", restEndpoint)
			return nil, shutdown, err
		}
		shutdownFuncs = append(shutdownFuncs, func() {
			err := lis.Close()
			if err != nil {
				rpcsLog.Errorf("Error closing listener: %v",
					err)
			}
		})

		wg.Add(1)
		go func() {
			rpcsLog.Infof("Password gRPC proxy started at %s",
				lis.Addr())
			wg.Done()
			_ = srv.Serve(lis)
		}()
	}

	// Wait for gRPC and REST servers to be up running.
	wg.Wait()

	// Wait for user to provide the password.
	ltndLog.Infof("Waiting for wallet encryption password. Use `lncli " +
		"create` to create a wallet, `lncli unlock` to unlock an " +
		"existing wallet, or `lncli changepassword` to change the " +
		"password of an existing wallet and unlock it.")

	// We currently don't distinguish between getting a password to be used
	// for creation or unlocking, as a new wallet db will be created if
	// none exists when creating the chain control.
	select {

	// The wallet is being created for the first time, we'll check to see
	// if the user provided any entropy for seed creation. If so, then
	// we'll create the wallet early to load the seed.
	case initMsg := <-pwService.InitMsgs:
		password := initMsg.Passphrase
		cipherSeed := initMsg.WalletSeed
		recoveryWindow := initMsg.RecoveryWindow

		// Before we proceed, we'll check the internal version of the
		// seed. If it's greater than the current key derivation
		// version, then we'll return an error as we don't understand
		// this.
		if cipherSeed.InternalVersion != keychain.KeyDerivationVersion {
			return nil, shutdown, fmt.Errorf("invalid internal "+
				"seed version %v, current version is %v",
				cipherSeed.InternalVersion,
				keychain.KeyDerivationVersion)
		}

		netDir := btcwallet.NetworkDir(
			chainConfig.ChainDir, cfg.ActiveNetParams.Params,
		)
		loader := wallet.NewLoader(
			cfg.ActiveNetParams.Params, netDir, !cfg.SyncFreelist,
			cfg.DB.Bolt.DBTimeout, recoveryWindow,
		)

		// With the seed, we can now use the wallet loader to create
		// the wallet, then pass it back to avoid unlocking it again.
		birthday := cipherSeed.BirthdayTime()
		newWallet, err := loader.CreateNewWallet(
			password, password, cipherSeed.Entropy[:], birthday,
		)
		if err != nil {
			// Don't leave the file open in case the new wallet
			// could not be created for whatever reason.
			if err := loader.UnloadWallet(); err != nil {
				ltndLog.Errorf("Could not unload new "+
					"wallet: %v", err)
			}
			return nil, shutdown, err
		}

		// For new wallets, the ResetWalletTransactions flag is a no-op.
		if cfg.ResetWalletTransactions {
			ltndLog.Warnf("Ignoring reset-wallet-transactions " +
				"flag for new wallet as it has no effect")
		}

		return &WalletUnlockParams{
			Password:        password,
			Birthday:        birthday,
			RecoveryWindow:  recoveryWindow,
			Wallet:          newWallet,
			ChansToRestore:  initMsg.ChanBackups,
			UnloadWallet:    loader.UnloadWallet,
			StatelessInit:   initMsg.StatelessInit,
			MacResponseChan: pwService.MacResponseChan,
		}, shutdown, nil

	// The wallet has already been created in the past, and is simply being
	// unlocked. So we'll just return these passphrases.
	case unlockMsg := <-pwService.UnlockMsgs:
		// Resetting the transactions is something the user likely only
		// wants to do once so we add a prominent warning to the log to
		// remind the user to turn off the setting again after
		// successful completion.
		if cfg.ResetWalletTransactions {
			ltndLog.Warnf("Dropped all transaction history from " +
				"on-chain wallet. Remember to disable " +
				"reset-wallet-transactions flag for next " +
				"start of lnd")
		}

		return &WalletUnlockParams{
			Password:        unlockMsg.Passphrase,
			RecoveryWindow:  unlockMsg.RecoveryWindow,
			Wallet:          unlockMsg.Wallet,
			ChansToRestore:  unlockMsg.ChanBackups,
			UnloadWallet:    unlockMsg.UnloadWallet,
			StatelessInit:   unlockMsg.StatelessInit,
			MacResponseChan: pwService.MacResponseChan,
		}, shutdown, nil

	case <-signal.ShutdownChannel():
		return nil, shutdown, fmt.Errorf("shutting down")
	}
}

// initializeDatabases extracts the current databases that we'll use for normal
// operation in the daemon. Two databases are returned: one remote and one
// local. However, only if the replicated database is active will the remote
// database point to a unique database. Otherwise, the local and remote DB will
// both point to the same local database. A function closure that closes all
// opened databases is also returned.
func initializeDatabases(ctx context.Context,
	cfg *Config) (*channeldb.DB, *channeldb.DB, func(), error) {

	ltndLog.Infof("Opening the main database, this might take a few " +
		"minutes...")

	if cfg.DB.Backend == lncfg.BoltBackend {
		ltndLog.Infof("Opening bbolt database, sync_freelist=%v, "+
			"auto_compact=%v", cfg.DB.Bolt.SyncFreelist,
			cfg.DB.Bolt.AutoCompact)
	}

	startOpenTime := time.Now()

	databaseBackends, err := cfg.DB.GetBackends(
		ctx, cfg.localDatabaseDir(), cfg.networkName(),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to obtain database "+
			"backends: %v", err)
	}

	// If the remoteDB is nil, then we'll just open a local DB as normal,
	// having the remote and local pointer be the exact same instance.
	var (
		localChanDB, remoteChanDB *channeldb.DB
		closeFuncs                []func()
	)
	if databaseBackends.RemoteDB == nil {
		// Open the channeldb, which is dedicated to storing channel,
		// and network related metadata.
		localChanDB, err = channeldb.CreateWithBackend(
			databaseBackends.LocalDB,
			channeldb.OptionSetRejectCacheSize(cfg.Caches.RejectCacheSize),
			channeldb.OptionSetChannelCacheSize(cfg.Caches.ChannelCacheSize),
			channeldb.OptionSetBatchCommitInterval(cfg.DB.BatchCommitInterval),
			channeldb.OptionDryRunMigration(cfg.DryRunMigration),
		)
		switch {
		case err == channeldb.ErrDryRunMigrationOK:
			return nil, nil, nil, err

		case err != nil:
			err := fmt.Errorf("unable to open local channeldb: %v", err)
			ltndLog.Error(err)
			return nil, nil, nil, err
		}

		closeFuncs = append(closeFuncs, func() {
			localChanDB.Close()
		})

		remoteChanDB = localChanDB
	} else {
		ltndLog.Infof("Database replication is available! Creating " +
			"local and remote channeldb instances")

		// Otherwise, we'll open two instances, one for the state we
		// only need locally, and the other for things we want to
		// ensure are replicated.
		localChanDB, err = channeldb.CreateWithBackend(
			databaseBackends.LocalDB,
			channeldb.OptionSetRejectCacheSize(cfg.Caches.RejectCacheSize),
			channeldb.OptionSetChannelCacheSize(cfg.Caches.ChannelCacheSize),
			channeldb.OptionSetBatchCommitInterval(cfg.DB.BatchCommitInterval),
			channeldb.OptionDryRunMigration(cfg.DryRunMigration),
		)
		switch {
		// As we want to allow both versions to get thru the dry run
		// migration, we'll only exit the second time here once the
		// remote instance has had a time to migrate as well.
		case err == channeldb.ErrDryRunMigrationOK:
			ltndLog.Infof("Local DB dry run migration successful")

		case err != nil:
			err := fmt.Errorf("unable to open local channeldb: %v", err)
			ltndLog.Error(err)
			return nil, nil, nil, err
		}

		closeFuncs = append(closeFuncs, func() {
			localChanDB.Close()
		})

		ltndLog.Infof("Opening replicated database instance...")

		remoteChanDB, err = channeldb.CreateWithBackend(
			databaseBackends.RemoteDB,
			channeldb.OptionDryRunMigration(cfg.DryRunMigration),
			channeldb.OptionSetBatchCommitInterval(cfg.DB.BatchCommitInterval),
		)
		switch {
		case err == channeldb.ErrDryRunMigrationOK:
			return nil, nil, nil, err

		case err != nil:
			localChanDB.Close()

			err := fmt.Errorf("unable to open remote channeldb: %v", err)
			ltndLog.Error(err)
			return nil, nil, nil, err
		}

		closeFuncs = append(closeFuncs, func() {
			remoteChanDB.Close()
		})
	}

	openTime := time.Since(startOpenTime)
	ltndLog.Infof("Database now open (time_to_open=%v)!", openTime)

	cleanUp := func() {
		for _, closeFunc := range closeFuncs {
			closeFunc()
		}
	}

	return localChanDB, remoteChanDB, cleanUp, nil
}

// initNeutrinoBackend inits a new instance of the neutrino light client
// backend given a target chain directory to store the chain state.
func initNeutrinoBackend(cfg *Config, chainDir string) (*neutrino.ChainService,
	func(), error) {

	// First we'll open the database file for neutrino, creating the
	// database if needed. We append the normalized network name here to
	// match the behavior of btcwallet.
	dbPath := filepath.Join(
		chainDir, lncfg.NormalizeNetwork(cfg.ActiveNetParams.Name),
	)

	// Ensure that the neutrino db path exists.
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		return nil, nil, err
	}

	dbName := filepath.Join(dbPath, "neutrino.db")
	db, err := walletdb.Create(
		"bdb", dbName, !cfg.SyncFreelist, cfg.DB.Bolt.DBTimeout,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create neutrino "+
			"database: %v", err)
	}

	headerStateAssertion, err := parseHeaderStateAssertion(
		cfg.NeutrinoMode.AssertFilterHeader,
	)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	// With the database open, we can now create an instance of the
	// neutrino light client. We pass in relevant configuration parameters
	// required.
	config := neutrino.Config{
		DataDir:      dbPath,
		Database:     db,
		ChainParams:  *cfg.ActiveNetParams.Params,
		AddPeers:     cfg.NeutrinoMode.AddPeers,
		ConnectPeers: cfg.NeutrinoMode.ConnectPeers,
		Dialer: func(addr net.Addr) (net.Conn, error) {
			dialAddr := addr
			if tor.IsOnionFakeIP(addr) {
				// Because the Neutrino address manager only
				// knows IP addresses, we need to turn any fake
				// tcp6 address that actually encodes an Onion
				// v2 address back into the hostname
				// representation before we can pass it to the
				// dialer.
				var err error
				dialAddr, err = tor.FakeIPToOnionHost(addr)
				if err != nil {
					return nil, err
				}
			}

			return cfg.net.Dial(
				dialAddr.Network(), dialAddr.String(),
				cfg.ConnectionTimeout,
			)
		},
		NameResolver: func(host string) ([]net.IP, error) {
			if tor.IsOnionHost(host) {
				// Neutrino internally uses btcd's address
				// manager which only operates on an IP level
				// and does not understand onion hosts. We need
				// to turn an onion host into a fake
				// representation of an IP address to make it
				// possible to connect to a block filter backend
				// that serves on an Onion v2 hidden service.
				fakeIP, err := tor.OnionHostToFakeIP(host)
				if err != nil {
					return nil, err
				}

				return []net.IP{fakeIP}, nil
			}

			addrs, err := cfg.net.LookupHost(host)
			if err != nil {
				return nil, err
			}

			ips := make([]net.IP, 0, len(addrs))
			for _, strIP := range addrs {
				ip := net.ParseIP(strIP)
				if ip == nil {
					continue
				}

				ips = append(ips, ip)
			}

			return ips, nil
		},
		AssertFilterHeader: headerStateAssertion,
	}

	neutrino.MaxPeers = 8
	neutrino.BanDuration = time.Hour * 48
	neutrino.UserAgentName = cfg.NeutrinoMode.UserAgentName
	neutrino.UserAgentVersion = cfg.NeutrinoMode.UserAgentVersion

	neutrinoCS, err := neutrino.NewChainService(config)
	if err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("unable to create neutrino light "+
			"client: %v", err)
	}

	if err := neutrinoCS.Start(); err != nil {
		db.Close()
		return nil, nil, err
	}

	cleanUp := func() {
		if err := neutrinoCS.Stop(); err != nil {
			ltndLog.Infof("Unable to stop neutrino light client: %v", err)
		}
		db.Close()
	}

	return neutrinoCS, cleanUp, nil
}

// parseHeaderStateAssertion parses the user-specified neutrino header state
// into a headerfs.FilterHeader.
func parseHeaderStateAssertion(state string) (*headerfs.FilterHeader, error) {
	if len(state) == 0 {
		return nil, nil
	}

	split := strings.Split(state, ":")
	if len(split) != 2 {
		return nil, fmt.Errorf("header state assertion %v in "+
			"unexpected format, expected format height:hash", state)
	}

	height, err := strconv.ParseUint(split[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid filter header height: %v", err)
	}

	hash, err := chainhash.NewHashFromStr(split[1])
	if err != nil {
		return nil, fmt.Errorf("invalid filter header hash: %v", err)
	}

	return &headerfs.FilterHeader{
		Height:     uint32(height),
		FilterHash: *hash,
	}, nil
}
