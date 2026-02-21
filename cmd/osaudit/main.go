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
	CLI     []string `json:"cli"`
}

func main() {
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

	auditPath, err := resolveAuditPath(repoRoot)
	if err != nil {
		fatalf("%v\n", err)
	}

	runMenu(commands, detectedOS, auditPath)
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

func resolveAuditPath(repoRoot string) (string, error) {
	base := filepath.Join(repoRoot, "cli", "audit")
	candidates := []string{base}
	if runtime.GOOS == "windows" {
		candidates = append([]string{base + ".exe"}, candidates...)
	}

	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, nil
		}
	}

	return "", fmt.Errorf("cli/audit not found under %s", filepath.Join(repoRoot, "cli"))
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

func runMenu(commands []auditCommand, detectedOS, auditPath string) {
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
		if err := runAuditCommand(auditPath, selected.CLI); err != nil {
			fmt.Printf("Command failed: %v\n", err)
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

func runAuditCommand(auditPath string, args []string) error {
	cmd := exec.Command(auditPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
