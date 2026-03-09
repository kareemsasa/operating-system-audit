// Build:
// go build -o dist/osaudit ./cmd/osaudit
//
// Run:
// ./dist/osaudit
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	embedded "github.com/kareemsasa/operating-system-audit"
	"github.com/kareemsasa/operating-system-audit/internal/diff"
	"github.com/kareemsasa/operating-system-audit/internal/latest"
)

type manifest struct {
	Commands []auditCommand `json:"commands"`
}

type auditCommand struct {
	ID      string              `json:"id"`
	Display string              `json:"display"`
	OSExec  map[string][]string `json:"os_exec"`
}

var commandIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

var validManifestOS = map[string]struct{}{
	"mac":     {},
	"linux":   {},
	"windows": {},
}

func main() {
	var exitCode int
	func() {
		defer func() {
			if extractedCleanup != nil {
				extractedCleanup()
			}
		}()
		exitCode = run(os.Args[1:])
	}()
	os.Exit(exitCode)
}

func run(args []string) int {
	detectedOS, err := detectOS()
	if err != nil {
		fatalf("%v\n", err)
	}

	repoRoot, err := resolveRepoRoot()
	if err != nil {
		fatalf("%v\n", err)
	}

	commands, err := loadCommands(filepath.Join(repoRoot, "cli", "commands.json"))
	if err != nil {
		fatalf("%v\n", err)
	}
	supported := commandsForCurrentOS(commands, detectedOS)
	noCommandsMessage := fmt.Sprintf("no commands available for detected OS: %s", detectedOS)

	if len(args) == 0 {
		if len(supported) == 0 {
			fmt.Println(noCommandsMessage)
			return 0
		}
		runMenu(supported, detectedOS, repoRoot)
		return 0
	}

	switch args[0] {
	case "list":
		if len(supported) == 0 {
			fmt.Println(noCommandsMessage)
			return 0
		}
		printCommandList(supported)
		return 0
	case "run":
		return runSubcommand(commands, repoRoot, detectedOS, args[1:])
	case "run-scheduled":
		return runRunScheduled(commands, repoRoot, detectedOS, args[1:])
	case "schedule":
		return runSchedule(repoRoot, args[1:])
	case "diff":
		return runDiff(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", args[0])
		printUsage()
		return 2
	}
}

func detectOS() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return "mac", nil
	case "linux":
		return "linux", nil
	case "windows":
		return "windows", nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func resolveRepoRoot() (string, error) {
	if override := strings.TrimSpace(os.Getenv("OSAUDIT_ROOT")); override != "" {
		return filepath.Clean(override), nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to resolve executable path: %w", err)
	}

	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		// Continue with non-symlink-resolved path if EvalSymlinks fails.
		exePath = filepath.Clean(exePath)
	}

	exeDir := filepath.Dir(exePath)
	candidates := []string{
		filepath.Dir(exeDir), // repoRoot/dist/osaudit -> repoRoot
		exeDir,               // repoRoot/osaudit -> repoRoot
	}

	for _, root := range candidates {
		manifestPath := filepath.Join(root, "cli", "commands.json")
		if _, err := os.Stat(manifestPath); err == nil {
			return root, nil
		}
	}

	// Fallback: extract embedded files to temp dir for standalone binary
	root, cleanup, err := extractEmbedded()
	if err != nil {
		return "", fmt.Errorf("could not determine repository root (set OSAUDIT_ROOT): %w", err)
	}
	// Store cleanup for main to defer; caller must call it when done
	extractedCleanup = cleanup
	return root, nil
}

var extractedCleanup func()

func extractEmbedded() (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "osaudit-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	err = fs.WalkDir(embedded.EmbeddedFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		dst := filepath.Join(tmpDir, path)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		data, err := fs.ReadFile(embedded.EmbeddedFS, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(path, ".sh") || strings.HasSuffix(path, ".py") {
			mode = 0o755
		}
		return os.WriteFile(dst, data, mode)
	})
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("extract embedded files: %w", err)
	}

	return tmpDir, cleanup, nil
}

func loadCommands(manifestPath string) ([]auditCommand, error) {
	file, err := os.Open(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("manifest not found: %s", manifestPath)
		}
		return nil, fmt.Errorf("failed to open manifest: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if err := validateManifest(filepath.Dir(filepath.Dir(manifestPath)), m); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	return m.Commands, nil
}

func validateManifest(repoRoot string, m manifest) error {
	if len(m.Commands) < 1 {
		return errors.New("commands must contain at least one entry")
	}

	seenIDs := make(map[string]int, len(m.Commands))

	for i, cmd := range m.Commands {
		if err := validateManifestCommand(repoRoot, cmd, i, seenIDs); err != nil {
			return err
		}
	}

	return nil
}

func validateManifestCommand(repoRoot string, cmd auditCommand, index int, seenIDs map[string]int) error {
	ref := fmt.Sprintf("command[%d]", index)
	id := strings.TrimSpace(cmd.ID)
	if id == "" {
		return fmt.Errorf("%s: id is required", ref)
	}
	ref = fmt.Sprintf("%s (%q)", ref, id)

	if !commandIDPattern.MatchString(id) {
		return fmt.Errorf("%s: id must match %q", ref, commandIDPattern.String())
	}
	if firstIndex, exists := seenIDs[id]; exists {
		return fmt.Errorf("%s: duplicate id %q (already defined at command[%d])", ref, id, firstIndex)
	}
	seenIDs[id] = index

	if strings.TrimSpace(cmd.Display) == "" {
		return fmt.Errorf("%s: display is required", ref)
	}
	if err := validateManifestOSExecTargets(repoRoot, ref, cmd.OSExec); err != nil {
		return err
	}

	return nil
}

func validateManifestOSExecTargets(repoRoot, ref string, osExec map[string][]string) error {
	if len(osExec) < 1 {
		return fmt.Errorf("%s: os_exec must contain at least one target", ref)
	}
	for osName, execValues := range osExec {
		if _, ok := validManifestOS[osName]; !ok {
			return fmt.Errorf("%s: os_exec contains unsupported OS key %q (allowed: mac, linux, windows)", ref, osName)
		}
		if err := validateManifestExecPath(repoRoot, fmt.Sprintf("%s: os_exec[%q]", ref, osName), execValues); err != nil {
			return err
		}
	}
	return nil
}

func validateManifestExecPath(repoRoot, ref string, execValues []string) error {
	if len(execValues) < 1 {
		return fmt.Errorf("%s: exec must contain at least one value", ref)
	}
	execPath := strings.TrimSpace(execValues[0])
	if execPath == "" {
		return fmt.Errorf("%s: exec[0] is required", ref)
	}
	if strings.HasPrefix(execPath, "-") {
		return fmt.Errorf("%s: exec[0] must not start with '-': %q", ref, execPath)
	}

	absoluteExecPath := filepath.Join(repoRoot, execPath)
	absoluteExecPath, err := filepath.Abs(absoluteExecPath)
	if err != nil {
		return fmt.Errorf("%s: failed to resolve absolute path for exec[0] %q: %w", ref, execPath, err)
	}
	info, err := os.Stat(absoluteExecPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s: exec[0] target does not exist: %s", ref, absoluteExecPath)
		}
		return fmt.Errorf("%s: failed to stat exec[0] target %s: %w", ref, absoluteExecPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s: exec[0] target is a directory, expected file: %s", ref, absoluteExecPath)
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s: exec[0] is not executable: %s (try: chmod +x %s)", ref, absoluteExecPath, absoluteExecPath)
	}

	return nil
}

// commandsForCurrentOS returns only commands that have an os_exec target for the given OS.
// Used for list and menu so users see only runnable commands.
func commandsForCurrentOS(commands []auditCommand, detectedOS string) []auditCommand {
	out := make([]auditCommand, 0, len(commands))
	for _, cmd := range commands {
		if _, ok := cmd.OSExec[detectedOS]; ok {
			out = append(out, cmd)
		}
	}
	return out
}

func commandExecForOS(cmd auditCommand, detectedOS string) ([]string, error) {
	if execValues, ok := cmd.OSExec[detectedOS]; ok {
		return execValues, nil
	}
	return nil, fmt.Errorf("command %q is not available on %q (no os_exec target configured)", cmd.ID, detectedOS)
}

func runMenu(commands []auditCommand, detectedOS, repoRoot string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Operating System Audit Tool")
	fmt.Printf("Detected OS: %s\n\n", detectedOS)

	for {
		choice, shouldExit, ok := selectCommand(reader, commands)
		if !ok {
			continue
		}
		if shouldExit {
			fmt.Println("Exiting.")
			return
		}

		selected := commands[choice-1]
		fmt.Printf("\nRunning: %s\n\n", selected.Display)
		if code, err := runAuditCommand(repoRoot, selected, detectedOS, nil, false, nil); err != nil {
			fmt.Printf("Command failed (exit %d): %v\n", code, err)
		}

		again, ok := promptRunAgain(reader)
		if !ok || !again {
			fmt.Println("Exiting.")
			return
		}
		fmt.Println()
	}
}

func selectCommand(reader *bufio.Reader, commands []auditCommand) (choice int, shouldExit bool, ok bool) {
	fmt.Println("Available commands:")
	for i, cmd := range commands {
		fmt.Printf("%d) %s\n", i+1, cmd.Display)
	}
	exitOption := len(commands) + 1
	fmt.Printf("%d) Exit\n\n", exitOption)

	fmt.Print("Select option: ")
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Input error: %v\n", err)
		return 0, false, false
	}

	choice, err = strconv.Atoi(strings.TrimSpace(input))
	if err != nil || choice < 1 || choice > exitOption {
		fmt.Println("Invalid selection. Please choose a listed option.")
		fmt.Println()
		return 0, false, false
	}

	if choice == exitOption {
		return 0, true, true
	}
	return choice, false, true
}

func promptRunAgain(reader *bufio.Reader) (bool, bool) {
	fmt.Print("\nRun another command? (y/n): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Input error: %v\n", err)
		return false, false
	}

	answer := strings.ToLower(strings.TrimSpace(input))
	return answer == "y" || answer == "yes", true
}

func runAuditCommand(repoRoot string, command auditCommand, detectedOS string, passthrough []string, printRunMeta bool, captureMeta *latest.RunMeta) (int, error) {
	execValues, err := commandExecForOS(command, detectedOS)
	if err != nil {
		return 1, err
	}

	targetPath, err := resolveCommandPath(repoRoot, execValues[0])
	if err != nil {
		return 1, err
	}

	args := append([]string{}, execValues[1:]...)
	args = append(args, passthrough...)

	var runMetaPath string
	if printRunMeta {
		tmpDir := filepath.Join(repoRoot, ".tmp")
		_ = os.MkdirAll(tmpDir, 0o755)
		f, err := os.CreateTemp(tmpDir, "osaudit-run-meta-*.json")
		if err != nil {
			return 1, fmt.Errorf("create temp file for run meta: %w", err)
		}
		runMetaPath = f.Name()
		f.Close()
		args = append(args, "--run-meta-out", runMetaPath)
		defer os.Remove(runMetaPath)
	}

	cmd := exec.Command(targetPath, args...)
	if printRunMeta {
		cmd.Stdout = os.Stderr // human output to stderr so stdout stays clean for JSON
	} else {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "OSAUDIT_ROOT="+repoRoot)

	err = cmd.Run()
	if err != nil {
		return exitCodeFromError(err), err
	}

	if printRunMeta && runMetaPath != "" {
		data, err := os.ReadFile(runMetaPath)
		if err != nil {
			return 1, fmt.Errorf("read run meta: %w", err)
		}
		if captureMeta != nil {
			if err := json.Unmarshal(data, captureMeta); err != nil {
				return 1, fmt.Errorf("parse run meta: %w", err)
			}
		} else {
			fmt.Println(string(data))
		}
	}
	return 0, nil
}

func resolveCommandPath(repoRoot, manifestPath string) (string, error) {
	path := filepath.Join(repoRoot, manifestPath)
	candidates := []string{path}
	if runtime.GOOS == "windows" && filepath.Ext(path) == "" {
		candidates = append([]string{path + ".exe"}, candidates...)
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("command executable not found: %s", path)
}

func runSubcommand(commands []auditCommand, repoRoot, detectedOS string, args []string) int {
	id, passthrough, printRunMeta, err := parseRunArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		printUsage()
		return 2
	}

	command, err := findCommandByID(commands, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	code, runErr := runAuditCommand(repoRoot, command, detectedOS, passthrough, printRunMeta, nil)
	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
		return code
	}
	return 0
}

func parseRunArgs(args []string) (id string, passthrough []string, printRunMeta bool, err error) {
	if len(args) == 0 {
		return "", nil, false, errors.New("missing command id for 'run'")
	}
	id = args[0]
	i := 1
	for i < len(args) && args[i] == "--print-run-meta" {
		printRunMeta = true
		i++
	}
	if i >= len(args) {
		return id, nil, printRunMeta, nil
	}
	if args[i] != "--" {
		return "", nil, false, errors.New("pass-through arguments must be after '--'")
	}
	return id, args[i+1:], printRunMeta, nil
}

func findCommandByID(commands []auditCommand, id string) (auditCommand, error) {
	for _, cmd := range commands {
		if cmd.ID == id {
			return cmd, nil
		}
	}
	return auditCommand{}, fmt.Errorf("unknown command id: %s", id)
}

func printCommandList(commands []auditCommand) {
	for _, cmd := range commands {
		fmt.Printf("%s %s\n", cmd.ID, cmd.Display)
	}
}

func runRunScheduled(commands []auditCommand, repoRoot, detectedOS string, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "run-scheduled requires audit id")
		printUsage()
		return 2
	}
	auditID := args[0]
	passthrough := []string{"--ndjson"}
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			passthrough = append(passthrough, args[i+1:]...)
			break
		}
	}

	command, err := findCommandByID(commands, auditID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var meta latest.RunMeta
	code, runErr := runAuditCommand(repoRoot, command, detectedOS, passthrough, true, &meta)
	if runErr != nil {
		fmt.Fprintln(os.Stderr, runErr)
		return code
	}
	if meta.NDJSON == "" {
		fmt.Fprintln(os.Stderr, "run-scheduled: audit did not produce NDJSON output")
		return 1
	}

	auditRoot := filepath.Dir(meta.Dir)
	baselinePath := filepath.Join(repoRoot, auditRoot, ".latest.json")
	var hasDeltas bool
	var capturedOutput []byte
	baselineData, err := os.ReadFile(baselinePath)
	hadBaseline := err == nil
	if hadBaseline {
		var baseline latest.RunMeta
		if err := json.Unmarshal(baselineData, &baseline); err != nil {
			fmt.Fprintf(os.Stderr, "run-scheduled: invalid baseline: %v\n", err)
			return 1
		}
		baselineNDJSON := filepath.Join(repoRoot, baseline.NDJSON)
		currentNDJSON := filepath.Join(repoRoot, meta.NDJSON)
		baselineRows, err := diff.ReadNDJSON(baselineNDJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "run-scheduled: read baseline NDJSON: %v\n", err)
			return 1
		}
		currentRows, err := diff.ReadNDJSON(currentNDJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "run-scheduled: read current NDJSON: %v\n", err)
			return 1
		}
		hasDeltas, capturedOutput = diff.Run(baselineRows, currentRows, false, true)
	}

	if err := latest.WriteLatestManifest(repoRoot, auditID, meta); err != nil {
		fmt.Fprintf(os.Stderr, "run-scheduled: write latest manifest: %v\n", err)
		return 1
	}
	if !hadBaseline {
		fmt.Fprintf(os.Stderr, "run-scheduled: no baseline found; wrote .latest.json\n")
	}

	if hasDeltas {
		if len(capturedOutput) > 0 {
			os.Stdout.Write(capturedOutput)
		}
		notifyOnChange(repoRoot, auditRoot, auditID)
		return 2
	}
	return 0
}

func notifyOnChange(repoRoot, auditRoot, auditID string) {
	title := "OS Audit: changes detected"
	body := fmt.Sprintf("Audit %s found changes since last run.", auditID)
	detectedOS, _ := detectOS()

	var notified bool
	switch detectedOS {
	case "mac":
		cmd := exec.Command("osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, body)
		if err := cmd.Run(); err == nil {
			notified = true
		}
	case "linux":
		cmd := exec.Command("notify-send", title, body)
		if err := cmd.Run(); err == nil {
			notified = true
		}
	}

	if !notified {
		alertsDir := filepath.Join(repoRoot, auditRoot, "alerts")
		_ = os.MkdirAll(alertsDir, 0o755)
		logName := fmt.Sprintf("%s.txt", strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", "-"))
		logPath := filepath.Join(alertsDir, logName)
		if err := os.WriteFile(logPath, []byte(fmt.Sprintf("%s\n%s\n", title, body)), 0o644); err == nil {
			fmt.Fprintf(os.Stderr, "run-scheduled: desktop notification unavailable; wrote alerts/%s\n", logName)
		} else {
			fmt.Fprintf(os.Stderr, "run-scheduled: desktop notification unavailable; could not write alerts/%s: %v\n", logName, err)
		}
	}
}

func runSchedule(repoRoot string, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "schedule requires subcommand: install, uninstall, status")
		printUsage()
		return 2
	}
	sub := args[0]
	rest := args[1:]
	if len(rest) < 1 {
		fmt.Fprintf(os.Stderr, "schedule %s requires audit id\n", sub)
		printUsage()
		return 2
	}
	auditID := rest[0]

	detectedOS, err := detectOS()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	switch sub {
	case "install":
		return scheduleInstall(repoRoot, auditID, detectedOS)
	case "uninstall":
		return scheduleUninstall(auditID, detectedOS)
	case "status":
		return scheduleStatus(auditID, detectedOS)
	default:
		fmt.Fprintf(os.Stderr, "schedule: unknown subcommand %q\n", sub)
		printUsage()
		return 2
	}
}

func scheduleInstall(repoRoot, auditID, detectedOS string) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "schedule install: %v\n", err)
		return 1
	}
	exe, _ = filepath.EvalSymlinks(exe)
	exe, _ = filepath.Abs(exe)

	args := []string{"run-scheduled", auditID, "--", "--redact-all"}

	if detectedOS == "linux" {
		configDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "schedule install: %v\n", err)
			return 1
		}
		unitName := "osaudit-" + auditID
		servicePath := filepath.Join(configDir, unitName+".service")
		timerPath := filepath.Join(configDir, unitName+".timer")

		serviceContent := fmt.Sprintf(`[Unit]
Description=OS Audit scheduled run (%s)

[Service]
Type=oneshot
SuccessExitStatus=2
WorkingDirectory=%s
Environment=OSAUDIT_ROOT=%s
ExecStart=%s %s
`, auditID, repoRoot, repoRoot, exe, strings.Join(args, " "))

		timerContent := fmt.Sprintf(`[Unit]
Description=OS Audit scheduled run (%s)

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
`, auditID)

		if err := os.WriteFile(servicePath, []byte(serviceContent), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "schedule install: %v\n", err)
			return 1
		}
		if err := os.WriteFile(timerPath, []byte(timerContent), 0o644); err != nil {
			os.Remove(servicePath)
			fmt.Fprintf(os.Stderr, "schedule install: %v\n", err)
			return 1
		}
		fmt.Printf("Installed. Reload and enable with:\n  systemctl --user daemon-reload\n  systemctl --user enable --now %s.timer\n", unitName)
		return 0
	}

	if detectedOS == "mac" {
		agentsDir := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")
		if err := os.MkdirAll(agentsDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "schedule install: %v\n", err)
			return 1
		}
		label := "com.osaudit." + auditID
		plistPath := filepath.Join(agentsDir, label+".plist")

		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>run-scheduled</string>
		<string>%s</string>
		<string>--</string>
		<string>--redact-all</string>
	</array>
	<key>WorkingDirectory</key>
	<string>%s</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>OSAUDIT_ROOT</key>
		<string>%s</string>
	</dict>
	<key>StartCalendarInterval</key>
	<dict>
		<key>Hour</key>
		<integer>8</integer>
		<key>Minute</key>
		<integer>0</integer>
	</dict>
	<key>StandardOutPath</key>
	<string>/dev/null</string>
	<key>StandardErrorPath</key>
	<string>/dev/null</string>
</dict>
</plist>
`, label, exe, auditID, repoRoot, repoRoot)

		if err := os.WriteFile(plistPath, []byte(plistContent), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "schedule install: %v\n", err)
			return 1
		}
		fmt.Printf("Installed. Load with: launchctl load %s\n", plistPath)
		return 0
	}

	fmt.Fprintln(os.Stderr, "schedule install: unsupported OS")
	return 1
}

func scheduleUninstall(auditID, detectedOS string) int {
	if detectedOS == "linux" {
		configDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
		unitName := "osaudit-" + auditID
		servicePath := filepath.Join(configDir, unitName+".service")
		timerPath := filepath.Join(configDir, unitName+".timer")

		// Stop and disable first
		exec.Command("systemctl", "--user", "stop", unitName+".timer").Run()
		exec.Command("systemctl", "--user", "disable", unitName+".timer").Run()

		os.Remove(timerPath)
		os.Remove(servicePath)
		fmt.Printf("Uninstalled %s\n", unitName)
		return 0
	}

	if detectedOS == "mac" {
		label := "com.osaudit." + auditID
		plistPath := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", label+".plist")

		exec.Command("launchctl", "unload", plistPath).Run()
		os.Remove(plistPath)
		fmt.Printf("Uninstalled %s\n", label)
		return 0
	}

	fmt.Fprintln(os.Stderr, "schedule uninstall: unsupported OS")
	return 1
}

func scheduleStatus(auditID, detectedOS string) int {
	if detectedOS == "linux" {
		unitName := "osaudit-" + auditID
		timerPath := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", unitName+".timer")
		if _, err := os.Stat(timerPath); err != nil {
			fmt.Printf("%s: not installed\n", auditID)
			return 0
		}
		fmt.Printf("%s: installed\n", auditID)
		cmd := exec.Command("systemctl", "--user", "list-timers", unitName+".timer", "--no-pager")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		return 0
	}

	if detectedOS == "mac" {
		label := "com.osaudit." + auditID
		plistPath := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", label+".plist")
		if _, err := os.Stat(plistPath); err != nil {
			fmt.Printf("%s: not installed\n", auditID)
			return 0
		}
		fmt.Printf("%s: installed (%s)\n", auditID, plistPath)
		fmt.Println("Next run: daily at 8:00 AM (launchd does not expose next run time)")
		return 0
	}

	fmt.Fprintln(os.Stderr, "schedule status: unsupported OS")
	return 1
}

func runDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	baseline := fs.String("baseline", "", "Path to baseline NDJSON file")
	current := fs.String("current", "", "Path to current NDJSON file")
	ndjson := fs.Bool("ndjson", false, "Emit structured diff rows as NDJSON instead of human-readable summary")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		printUsage()
		return 2
	}
	if *baseline == "" || *current == "" {
		fmt.Fprintln(os.Stderr, "diff requires --baseline and --current")
		printUsage()
		return 2
	}

	baselineRows, err := diff.ReadNDJSON(*baseline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	currentRows, err := diff.ReadNDJSON(*current)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	hasDeltas, _ := diff.Run(baselineRows, currentRows, *ndjson, false)
	if hasDeltas {
		return 2
	}
	return 0
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  osaudit")
	fmt.Fprintln(os.Stderr, "  osaudit list")
	fmt.Fprintln(os.Stderr, "  osaudit run <id> [--print-run-meta] -- [args...]")
	fmt.Fprintln(os.Stderr, "  osaudit run-scheduled <audit_id> [--] [args...]")
	fmt.Fprintln(os.Stderr, "  osaudit schedule install|uninstall|status <audit_id>")
	fmt.Fprintln(os.Stderr, "  osaudit diff --baseline <path> --current <path> [--ndjson]")
}

func exitCodeFromError(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
