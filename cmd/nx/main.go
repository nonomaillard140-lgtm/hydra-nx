package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hydra/internal/api"
	"hydra/internal/auth"
	"hydra/internal/license"
	"hydra/internal/notify"
	"hydra/internal/publiclists"
	"hydra/internal/scan"
	"hydra/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "worker":
		err = runWorker(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "selfinstall":
		err = runSelfInstall(os.Args[2:])
	case "backup":
		err = runBackup(os.Args[2:])
	case "restore":
		err = runRestore(os.Args[2:])
	case "passwd":
		err = runPasswd(os.Args[2:])
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "doctor":
		err = runDoctor(os.Args[2:])
	case "publish-list":
		err = runPublishList(os.Args[2:])
	case "cleanup":
		err = runCleanup(os.Args[2:])
	case "version":
		fmt.Printf("nx 1.0.0 %s/%s\n", runtime.GOOS, runtime.GOARCH)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		err = errors.New("sous-commande inconnue: " + os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nx:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `nx — console HYDRA défensive

Sous-commandes:
  serve [--addr :8080] [--data ./data]
  worker [--data ./data]
  migrate [--data ./data] [--to user@hôte]
  selfinstall [--prefix /opt/hydra] [--data /var/lib/hydra]
  backup [--data ./data] [--file hydra-backup.tar.gz]
  restore [--data ./data-restored] --file hydra-backup.tar.gz
  passwd --admin [--data ./data]
  keygen [--data ./data]
  doctor [--data ./data] [--addr :8080]
  publish-list --file X --name Y --kind L7|L4|PATHS [--data ./data]
  cleanup [--data ./data]`)
}

func dataFlag(fs *flag.FlagSet) *string {
	return fs.String("data", envOr("HYDRA_DATA", "./data"), "répertoire de données")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func openStore(ctx context.Context, data string, migrate bool) (*store.Store, error) {
	st, err := store.Open(ctx, data)
	if err != nil {
		return nil, err
	}
	if migrate {
		if err := st.Migrate(ctx); err != nil {
			st.Close()
			return nil, err
		}
	}
	return st, nil
}

func intSetting(ctx context.Context, st *store.Store, key string, fallback int) int {
	value, err := strconv.Atoi(st.StringSetting(ctx, key, strconv.Itoa(fallback)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func newScheduler(ctx context.Context, st *store.Store) *scan.Scheduler {
	scheduler := scan.NewScheduler(st, intSetting(ctx, st, "concurrency", 4), intSetting(ctx, st, "timeout_seconds", 12), intSetting(ctx, st, "host_limit", 2))
	dispatcher := notify.NewDispatcher(st)
	scheduler.Scanner().OnHit = func(hit store.Hit) {
		message := fmt.Sprintf("HYDRA — nouvelle exposition rédigée\nHôte: %s\nType: %s\nService: %s\nStatut: %s\nPreuve: %s", hit.Host, hit.Vuln, hit.Service, hit.Status, hit.SecretRedacted)
		dispatcher.Dispatch(context.Background(), hit.UserID, hit.Service, message)
	}
	return scheduler
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	data := dataFlag(fs)
	addr := fs.String("addr", envOr("HYDRA_ADDR", ":8080"), "adresse HTTP d'écoute")
	secure := fs.Bool("secure-cookie", os.Getenv("HYDRA_SECURE_COOKIE") == "true", "cookie Secure derrière HTTPS")
	tlsCert := fs.String("tls-cert", os.Getenv("HYDRA_TLS_CERT"), "certificat TLS optionnel")
	tlsKey := fs.String("tls-key", os.Getenv("HYDRA_TLS_KEY"), "clé TLS optionnelle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	authService := auth.NewService(st)
	credentials, err := authService.EnsureAdmin(ctx)
	if err != nil {
		return err
	}
	if credentials != nil {
		fmt.Printf("Compte administrateur initial (affiché une seule fois)\nUtilisateur: %s\nEmail: %s\nMot de passe: %s\n", credentials.Username, credentials.Email, credentials.Password)
	}
	scheduler := newScheduler(ctx, st)
	scheduler.Start(ctx)
	defer scheduler.Stop()
	server := api.NewServer(st, authService, scheduler, *secure || *tlsCert != "")
	httpServer := &http.Server{Addr: *addr, Handler: server.Router(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 1 << 20}
	go cleanupLoop(ctx, st)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("tls-cert et tls-key doivent être fournis ensemble")
	}
	fmt.Printf("HYDRA écoute sur %s\n", *addr)
	if *tlsCert != "" {
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = httpServer.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = httpServer.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func runWorker(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	data := dataFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	scheduler := newScheduler(ctx, st)
	scheduler.Start(ctx)
	cleanupLoop(ctx, st)
	scheduler.Stop()
	return nil
}

func cleanupLoop(ctx context.Context, st *store.Store) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := st.Cleanup(ctx, time.Now().UTC()); err != nil {
				slog.Error("nettoyage planifié", "error", err)
			}
		}
	}
}

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	data := dataFlag(fs)
	to := fs.String("to", "", "destination SSH user@hôte")
	remoteDir := fs.String("remote-dir", "/opt/hydra", "répertoire distant du binaire")
	remoteData := fs.String("remote-data", "/var/lib/hydra", "répertoire distant des données")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to != "" {
		return remoteMigrate(*data, *to, *remoteDir, *remoteData)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	fmt.Println("Migrations SQLite appliquées.")
	return nil
}

func runBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	data := dataFlag(fs)
	destination := fs.String("file", "hydra-backup-"+time.Now().UTC().Format("20060102T150405Z")+".tar.gz", "archive de destination")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Backup(ctx, *destination); err != nil {
		return err
	}
	fmt.Println(*destination)
	return nil
}

func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	data := dataFlag(fs)
	source := fs.String("file", "", "archive de sauvegarde")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := store.RestoreArchive(*source, *data); err != nil {
		return err
	}
	fmt.Println("Restauration terminée; sessions et clés conservées.")
	return nil
}

func runPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	data := dataFlag(fs)
	admin := fs.Bool("admin", false, "réinitialiser le compte admin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*admin {
		return errors.New("--admin est requis")
	}
	ctx := context.Background()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	password, err := auth.NewService(st).ResetAdminPassword(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Nouveau mot de passe admin: %s\n", password)
	return nil
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	data := dataFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	public, err := license.NewManager(st).PublicKey()
	if err != nil {
		return err
	}
	fmt.Println(public)
	return nil
}

func runPublishList(args []string) error {
	fs := flag.NewFlagSet("publish-list", flag.ContinueOnError)
	data := dataFlag(fs)
	source := fs.String("file", "", "fichier source")
	name := fs.String("name", "", "nom public")
	kind := fs.String("kind", "", "L7, L4 ou PATHS")
	format := fs.String("format", "", "txt ou csv; déduit de l'extension")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	item, err := publiclists.NewService(st).Publish(ctx, *source, *name, *kind, *format, 0)
	if err != nil {
		return err
	}
	fmt.Printf("Publié: id=%d lignes=%d sha256=%s\n", item.ID, item.Lines, item.SHA256)
	return nil
}

func runCleanup(args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	data := dataFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := openStore(context.Background(), *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Cleanup(context.Background(), time.Now().UTC()); err != nil {
		return err
	}
	fmt.Println("Sessions expirées et envois de plus de 90 jours supprimés.")
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	data := dataFlag(fs)
	addr := fs.String("addr", envOr("HYDRA_ADDR", ":8080"), "adresse à tester")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := openStore(ctx, *data, true)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.DB().PingContext(ctx); err != nil {
		return err
	}
	fmt.Println("OK SQLite et migrations")
	if err := os.WriteFile(filepath.Join(*data, ".doctor"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600); err != nil {
		return fmt.Errorf("permissions données: %w", err)
	}
	_ = os.Remove(filepath.Join(*data, ".doctor"))
	fmt.Println("OK permissions du répertoire de données")
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("port %s: %w", *addr, err)
	}
	_ = listener.Close()
	fmt.Println("OK port d'écoute disponible")
	if _, err := net.DefaultResolver.LookupHost(ctx, "localhost"); err != nil {
		return fmt.Errorf("DNS local: %w", err)
	}
	fmt.Println("OK résolution DNS locale")
	var stat syscall.Statfs_t
	if err := syscall.Statfs(*data, &stat); err != nil {
		return err
	}
	free := stat.Bavail * uint64(stat.Bsize)
	fmt.Printf("OK espace disponible: %d Mio\n", free/1024/1024)
	if offset := time.Now().UTC().Sub(time.Now()); offset > time.Minute || offset < -time.Minute {
		return errors.New("horloge système incohérente")
	}
	fmt.Println("OK horloge système")
	fmt.Println("Sortie réseau et addons: vérification à la demande depuis la console, sans secrets découverts.")
	return nil
}

func runSelfInstall(args []string) error {
	fs := flag.NewFlagSet("selfinstall", flag.ContinueOnError)
	prefix := fs.String("prefix", "/opt/hydra", "répertoire du binaire")
	data := fs.String("data", "/var/lib/hydra", "répertoire des données")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("selfinstall nécessite root; install.sh gère aussi l'utilisateur système")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*prefix, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(*data, 0o750); err != nil {
		return err
	}
	input, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(filepath.Join(*prefix, "nx"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := output.ReadFrom(input); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	unit := fmt.Sprintf("[Unit]\nDescription=HYDRA defensive scanner\nAfter=network-online.target\n\n[Service]\nType=simple\nExecStart=%s serve --data %s --addr 127.0.0.1:8080 --secure-cookie\nRestart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=%s\n\n[Install]\nWantedBy=multi-user.target\n", filepath.Join(*prefix, "nx"), *data, *data)
	if err := os.WriteFile("/etc/systemd/system/hydra.service", []byte(unit), 0o644); err != nil {
		return err
	}
	if output, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemd daemon-reload: %s", output)
	}
	fmt.Println("Binaire et unité installés. Créez un utilisateur de service avec deploy/install.sh pour une installation durcie complète.")
	return nil
}

func remoteMigrate(data, destination, remoteDir, remoteData string) error {
	if !strings.Contains(destination, "@") || strings.ContainsAny(destination, "\r\n ;") {
		return errors.New("destination SSH invalide")
	}
	archive := filepath.Join(os.TempDir(), "hydra-migrate-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".tar.gz")
	defer os.Remove(archive)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	st, err := openStore(ctx, data, true)
	if err != nil {
		return err
	}
	if err := st.Backup(ctx, archive); err != nil {
		st.Close()
		return err
	}
	st.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	remoteArchive := "/tmp/hydra-migrate.tar.gz"
	commands := [][]string{
		{"ssh", destination, "mkdir", "-p", remoteDir, remoteData + ".new"},
		{"scp", executable, destination + ":" + remoteDir + "/nx.new"},
		{"scp", archive, destination + ":" + remoteArchive},
	}
	for _, command := range commands {
		if output, err := exec.CommandContext(ctx, command[0], command[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %s", command[0], output)
		}
	}
	script := fmt.Sprintf("set -eu; chmod 755 %s/nx.new; %s/nx.new restore --file %s --data %s.new; systemctl stop hydra; if [ -d %s.previous ]; then rm -rf %s.previous; fi; if [ -d %s ]; then mv %s %s.previous; fi; mv %s.new %s; mv %s/nx.new %s/nx; systemctl start hydra; rm -f %s",
		shellQuote(remoteDir), shellQuote(remoteDir), shellQuote(remoteArchive), shellQuote(remoteData), shellQuote(remoteData), shellQuote(remoteData), shellQuote(remoteData), shellQuote(remoteData), shellQuote(remoteData), shellQuote(remoteData), shellQuote(remoteData), shellQuote(remoteDir), shellQuote(remoteDir), shellQuote(remoteArchive))
	if output, err := exec.CommandContext(ctx, "ssh", destination, script).CombinedOutput(); err != nil {
		return fmt.Errorf("bascule distante: %s", output)
	}
	fmt.Println("Migration distante terminée; sauvegarde précédente conservée avec suffixe .previous.")
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
