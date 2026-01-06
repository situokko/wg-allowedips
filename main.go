// wg-allowedips.go - Generate WireGuard AllowedIPs list from config file
//
// Usage:
//   wg-allowedips <allowed-file>                  - Output comma-separated IPs
//   wg-allowedips <allowed-file> <wg-config>      - Output wg-config with AllowedIPs replaced
//
// Allowed file format:
//   # This is a comment
//   10.0.0.1
//   192.168.1.0
//   example.com

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

const (
	colorRed    = "\033[0;31m"
	colorYellow = "\033[0;33m"
	colorReset  = "\033[0m"
)

func errorExit(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorRed+"ERROR: "+format+colorReset+"\n", args...)
	os.Exit(1)
}

func warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, colorYellow+"WARNING: "+format+colorReset+"\n", args...)
}

// isValidIPv4 checks if the string is a valid IPv4 address
func isValidIPv4(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return false
	}
	// Check for leading zeros
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) > 1 && part[0] == '0' {
			return false
		}
	}
	return true
}

// isValidHostname checks if the string is a valid hostname (RFC 1123)
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Hostname label pattern
	labelPattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)

	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// resolveHostname uses dig to resolve a hostname to IPv4 addresses
func resolveHostname(hostname string) ([]string, error) {
	cmd := exec.Command("dig", "+short", hostname)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var ips []string
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Only include valid IPv4 addresses (dig might return CNAMEs too)
		if ip := net.ParseIP(line); ip != nil && ip.To4() != nil {
			ips = append(ips, line)
		}
	}
	return ips, nil
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <allowed-file> [wg-config]\n", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		usage()
	}

	configFile := os.Args[1]
	var wgConfigFile string
	if len(os.Args) == 3 {
		wgConfigFile = os.Args[2]
	}

	// Open config file
	file, err := os.Open(configFile)
	if err != nil {
		errorExit("Config file does not exist: %s", configFile)
	}
	defer file.Close()

	var allIPs []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		if isValidIPv4(line) {
			allIPs = append(allIPs, line)
		} else if isValidHostname(line) {
			// Resolve hostname
			resolvedIPs, err := resolveHostname(line)
			if err != nil {
				warn("Line %d: Failed to resolve hostname %s: %v", lineNum, line, err)
				continue
			}
			if len(resolvedIPs) == 0 {
				warn("Line %d: No DNS results for hostname: %s", lineNum, line)
			} else {
				allIPs = append(allIPs, resolvedIPs...)
			}
		} else {
			errorExit("Line %d: Invalid entry (not an IPv4 or hostname): %s", lineNum, line)
		}
	}

	if err := scanner.Err(); err != nil {
		errorExit("Error reading config file: %v", err)
	}

	// Remove duplicates and sort
	allIPs = removeDuplicates(allIPs)
	sort.Strings(allIPs)

	allowedIPsValue := strings.Join(allIPs, ",")

	// Output mode depends on whether wg-config was provided
	if wgConfigFile == "" {
		// Just output comma-separated list
		if len(allIPs) > 0 {
			fmt.Println(allowedIPsValue)
		}
	} else {
		// Read and output wg-config with AllowedIPs replaced
		wgFile, err := os.Open(wgConfigFile)
		if err != nil {
			errorExit("WireGuard config file does not exist: %s", wgConfigFile)
		}
		defer wgFile.Close()

		wgScanner := bufio.NewScanner(wgFile)
		for wgScanner.Scan() {
			line := wgScanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "AllowedIPs") {
				fmt.Printf("AllowedIPs = %s\n", allowedIPsValue)
			} else {
				fmt.Println(line)
			}
		}

		if err := wgScanner.Err(); err != nil {
			errorExit("Error reading WireGuard config file: %v", err)
		}
	}
}
