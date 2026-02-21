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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type manifest struct {
	Commands []auditCommand `json:"commands"`
}

type auditCommand struct {
	ID      string   `json:"id"`
	OS      []string `json:"os"`
	Display string   `json:"display"`
	Exec    []string `json:"exec"`
}

func main() {
	exitCode := run(os.Args[1:])
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

	commands, err := loadCommands(filepath.Join(repoRoot, "cli", "commands.json"), detectedOS)
	if err != nil {
		fatalf("%v\n", err)
	}

	if len(args) == 0 {
		runMenu(commands, detectedOS, repoRoot)
		return 0
	}

	switch args[0] {
	case "list":
		printCommandList(commands)
		return 0
	case "run":
		return runSubcommand(commands, repoRoot, args[1:])
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

	return "", errors.New("could not determine repository root (set OSAUDIT_ROOT)")
}

func loadCommands(manifestPath, detectedOS string) ([]auditCommand, error) {
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

	filtered := make([]auditCommand, 0, len(m.Commands))
	for _, cmd := range m.Commands {
		if commandSupportsOS(cmd, detectedOS) {
			if len(cmd.Exec) == 0 {
				return nil, fmt.Errorf("invalid command '%s': exec field is required", cmd.ID)
			}
			filtered = append(filtered, cmd)
		}
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("no commands available for detected OS: %s", detectedOS)
	}

	return filtered, nil
}

func commandSupportsOS(cmd auditCommand, detectedOS string) bool {
	for _, osName := range cmd.OS {
		if osName == detectedOS {
			return true
		}
	}
	return false
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
		if code, err := runAuditCommand(repoRoot, selected, nil); err != nil {
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

func runAuditCommand(repoRoot string, command auditCommand, passthrough []string) (int, error) {
	targetPath, err := resolveCommandPath(repoRoot, command.Exec[0])
	if err != nil {
		return 1, err
	}

	args := append([]string{}, command.Exec[1:]...)
	args = append(args, passthrough...)

	cmd := exec.Command(targetPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "OSAUDIT_ROOT="+repoRoot)

	err = cmd.Run()
	if err == nil {
		return 0, nil
	}
	return exitCodeFromError(err), err
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

func runSubcommand(commands []auditCommand, repoRoot string, args []string) int {
	id, passthrough, err := parseRunArgs(args)
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

	code, runErr := runAuditCommand(repoRoot, command, passthrough)
	if runErr != nil {
		return code
	}
	return 0
}

func parseRunArgs(args []string) (string, []string, error) {
	if len(args) == 0 {
		return "", nil, errors.New("missing command id for 'run'")
	}
	id := args[0]

	if len(args) == 1 {
		return id, nil, nil
	}
	if args[1] != "--" {
		return "", nil, errors.New("pass-through arguments must be after '--'")
	}
	return id, args[2:], nil
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
		fmt.Printf("%s\t%s\n", cmd.ID, cmd.Display)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  osaudit")
	fmt.Fprintln(os.Stderr, "  osaudit list")
	fmt.Fprintln(os.Stderr, "  osaudit run <id> -- [args...]")
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
