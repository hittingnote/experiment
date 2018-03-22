// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/daemon/defaults"

	"github.com/spf13/cobra"
)

// BugtoolRootCmd is the top level command for the bugtool.
var BugtoolRootCmd = &cobra.Command{
	Use:   "bugtool",
	Short: "Cilium agent debugging tool",
	Long:  "cilium-bugtool - capture system and node information for debugging a Cilium node",
	Example: `	# Create archive with files
	$ cilium-bugtool
	[...]

	# Serving files over HTTP
	$ cilium-bugtool --serve
	[...]

	# Retrieve archive from a Cilium Kubernetes pod
	$ kubectl get pods --namespace kube-system
	NAME                          READY     STATUS    RESTARTS   AGE
	cilium-kg8lv                  1/1       Running   0          13m
	[...]
	$ kubectl -n kube-system exec cilium-kg8lv cilium-bugtool
	$ kubectl cp kube-system/cilium-kg8lv:/tmp/cilium-bugtool-243785589.tar /tmp/cilium-bugtool-243785589.tar`,
	Run: func(cmd *cobra.Command, args []string) {
		runTool()
	},
}

const (
	disclaimer = `DISCLAIMER
This tool has copied information about your environment.
If you are going to register a issue on GitHub, please
only provide files from the archive you have reviewed
for sensitive information.
`
)

var (
	archive      bool
	k8s          bool
	serve        bool
	port         int
	dumpPath     string
	host         string
	k8sNamespace string
	k8sLabel     string
	execTimeout  time.Duration
	configPath   string
	dryRunMode   bool
)

func init() {
	BugtoolRootCmd.Flags().BoolVar(&archive, "archive", true, "Create archive when false skips deletion of the output directory")
	BugtoolRootCmd.Flags().BoolVar(&serve, "serve", false, "Start HTTP server to serve static files")
	BugtoolRootCmd.Flags().BoolVar(&k8s, "k8s-mode", false, "Require Kubernetes pods to be found or fail")
	BugtoolRootCmd.Flags().BoolVar(&dryRunMode, "dry-run", false, "Create configuration file of all commands that would have been executed")
	BugtoolRootCmd.Flags().IntVarP(&port, "port", "p", 4444, "Port to use for the HTTP server, (default 4444)")
	BugtoolRootCmd.Flags().StringVarP(&dumpPath, "tmp", "t", "/tmp", "Path to store extracted files")
	BugtoolRootCmd.Flags().StringVarP(&host, "host", "H", "", "URI to server-side API")
	BugtoolRootCmd.Flags().StringVarP(&k8sNamespace, "k8s-namespace", "", "kube-system", "Kubernetes namespace for Cilium pod")
	BugtoolRootCmd.Flags().StringVarP(&k8sLabel, "k8s-label", "", "k8s-app=cilium", "Kubernetes label for Cilium pod")
	BugtoolRootCmd.Flags().DurationVarP(&execTimeout, "exec-timeout", "", 30*time.Second, "The default timeout for any cmd execution in seconds")
	BugtoolRootCmd.Flags().StringVarP(&configPath, "config", "", "./.cilium-bugtool.config", "Configuration to decide what should be run")
}

func getVerifyCiliumPods() []string {
	// By default try to pick either Kubernetes or non-k8s (host mode). If
	// we find Cilium pod(s) then it's k8s-mode otherwise host mode.
	// Passing extra flags can override the default.
	k8sPods, err := getCiliumPods(k8sNamespace, k8sLabel)
	switch {
	case k8s:
		// When the k8s flag is set, perform extra checks that we actually do have pods or fail.
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\nFailed to find pods, is kube-apiserver running?\n", err)
			os.Exit(1)
		}
		if len(k8sPods) < 1 {
			fmt.Fprint(os.Stderr, "Found no pods, is kube-apiserver running?\n")
			os.Exit(1)
		}
	case os.Getuid() != 0 && len(k8sPods) == 0:
		// When the k8s flag is not set and the user is not root,
		// debuginfo and BPF related commands can fail.
		fmt.Printf("Warning, some of the BPF commands might fail when run as not root\n")
	}

	return k8sPods
}

func removeIfEmpty(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open directory %s\n", err)
		return
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read directory %s\n", err)
		return
	} else if len(files) == 0 {
		if err := os.Remove(dir); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to delete directory %s\n", err)
			return
		}
	}

	fmt.Printf("Deleted empty directory %s\n", dir)
}

func runTool() {
	// Prevent collision with other directories
	nowStr := time.Now().Format("20060102-150405.999-0700-MST")
	prefix := fmt.Sprintf("cilium-bugtool-%s-", nowStr)
	dbgDir, err := ioutil.TempDir(dumpPath, prefix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create debug directory %s\n", err)
		os.Exit(1)
	}
	defer cleanup(dbgDir)
	cmdDir := createDir(dbgDir, "cmd")
	confDir := createDir(dbgDir, "conf")

	k8sPods := getVerifyCiliumPods()

	var commands []string
	if dryRunMode {
		dryRun(configPath, k8sPods, confDir, cmdDir)
		fmt.Printf("Configuration file at %s\n", configPath)
		return
	}

	// Check if there is a user supplied configuration
	if config, _ := loadConfigFile(configPath); config != nil {
		// All of of the commands run are from the configuration file
		commands = config.Commands
	}
	if len(commands) == 0 {
		// Found no configuration file or empty so fall back to default commands.
		commands = defaultCommands(confDir, cmdDir, k8sPods)
	}
	defer printDisclaimer()

	runAll(commands, cmdDir, k8sPods)

	removeIfEmpty(cmdDir)
	removeIfEmpty(confDir)

	// Please don't change the output below for the archive or directory.
	// The order matters and is being used by scripts to copy the right
	// file(s).
	if archive {
		archivePath, err := createArchive(dbgDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create archive %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nARCHIVE at %s\n", archivePath)
	} else {
		fmt.Printf("\nDIRECTORY at %s\n", dbgDir)
	}

	if serve {
		// Use signal handler to cleanup after serving
		setupSigHandler(dbgDir)
		serveStaticFiles(dbgDir)
	}
}

// dryRun creates the configuration file to show the user what would have been run.
// The same file can be used to modify what will be run by the bugtool.
func dryRun(configPath string, k8sPods []string, confDir, cmdDir string) {
	_, err := setupDefaultConfig(configPath, k8sPods, confDir, cmdDir)
	if err != nil {
		fmt.Printf("Error: %s", err)
		os.Exit(1)
	}
}

func printDisclaimer() {
	fmt.Print(disclaimer)
}

func cleanup(dbgDir string) {
	if !archive {
		// Preserve directory when archive is not created
		return
	}
	if err := os.RemoveAll(dbgDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to cleanup temporary files %s\n", err)
	}
}

func setupSigHandler(dbgDir string) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for range signalChan {
			printDisclaimer()
			cleanup(dbgDir)
			os.Exit(0)
		}
	}()
}

func serveStaticFiles(debugDirectory string) {
	fs := http.FileServer(http.Dir(debugDirectory))
	addr := fmt.Sprintf(":%d", port)

	http.Handle("/", fs)
	fmt.Printf("Serving files at http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Could not start server %s\n", err)
	}
}

func createDir(dbgDir string, newDir string) string {
	confDir := filepath.Join(dbgDir, newDir)
	if err := os.Mkdir(confDir, defaults.RuntimePathRights); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create %s info directory %s\n", newDir, err)
		return dbgDir
	}
	return confDir
}

func podPrefix(pod, cmd string) string {
	return fmt.Sprintf("kubectl exec %s -n %s -- %s", pod, k8sNamespace, cmd)
}

func runAll(commands []string, cmdDir string, k8sPods []string) {
	var numRoutinesAtOnce int
	// Perform sanity check to prevent division by zero
	if l := len(commands); l > 1 {
		numRoutinesAtOnce = l / 2
	} else if l == 1 {
		numRoutinesAtOnce = l
	} else {
		// No commands
		return
	}
	semaphore := make(chan bool, numRoutinesAtOnce)
	for i := 0; i < numRoutinesAtOnce; i++ {
		// This will not block because the channel is buffered and we
		// can write to it numRoutinesAtOnce before the write blocks
		semaphore <- true
	}

	wg := sync.WaitGroup{}
	for _, cmd := range commands {
		if strings.Contains(cmd, "tables") {
			// iptables commands hold locks so we can't have multiple runs. They
			// have to be run one at a time to avoid 'Another app is currently
			// holding the xtables lock...'
			writeCmdToFile(cmdDir, cmd, k8sPods)
			continue
		}
		// Tell the wait group it needs to track another goroutine
		wg.Add(1)

		// Start a subroutine to run our command
		go func(cmd string) {
			// Once we exit this goroutine completely, signal the
			// original that we are done
			defer wg.Done()

			// This will wait until an entry in this channel is
			// available to read. We started with numRoutinesAtOnce
			// in there (from above)
			<-semaphore
			// When we are done we return the thing we took from
			// the semaphore, so another goroutine can get it
			defer func() { semaphore <- true }()
			writeCmdToFile(cmdDir, cmd, k8sPods)
		}(cmd)
	}
	// Wait for all the spawned goroutines to finish up.
	wg.Wait()
}

func execCommand(cmd string, args ...string) (string, error) {
	fmt.Printf("exec: %s %s\n", cmd, args)
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, cmd, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("exec timeout")
	}
	return string(output), err
}

// writeCmdToFile will execute command and write markdown output to a file
func writeCmdToFile(cmdDir, prompt string, k8sPods []string) {
	// Clean up the filename
	name := strings.Replace(prompt, "/", " ", -1)
	name = strings.Replace(name, " ", "-", -1)
	f, err := os.Create(filepath.Join(cmdDir, name+".md"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create file %s\n", err)
		return
	}
	defer f.Close()

	cmd, args := split(prompt)

	if len(k8sPods) == 0 {
		// The command does not exist, abort.
		if _, err := exec.LookPath(cmd); err != nil {
			os.Remove(f.Name())
			return
		}
	} else if len(args) > 5 {
		// Boundary check is necessary to skip other non exec kubectl
		// commands.
		ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
		defer cancel()
		if _, err := exec.CommandContext(ctx, "kubectl", "exec",
			args[1], "-n", args[3], "--", "which",
			args[5]).CombinedOutput(); err != nil || ctx.Err() == context.DeadlineExceeded {
			os.Remove(f.Name())
			return
		}
	}
	// Write prompt as header and the output as body, and / or error but delete empty output.
	output, err := execCommand(cmd, args...)
	if err != nil {
		fmt.Fprintf(f, fmt.Sprintf("> Error while running '%s':  %s\n\n", prompt, err))
	}
	// We deliberately continue in case there was a error but the output
	// produced might have useful information
	if strings.Contains(output, "```") {
		// Already contains Markdown, print as is.
		fmt.Fprint(f, output)
	} else if len(output) > 0 {
		fmt.Fprintf(f, fmt.Sprintf("# %s\n\n```\n%s\n```\n", prompt, output))
	} else {
		// Empty file
		os.Remove(f.Name())
	}
}

// split takes a command prompt and returns the command and arguments separately
func split(prompt string) (string, []string) {
	// Split the command and arguments
	split := strings.Split(prompt, " ")
	argc := len(split)
	var args []string
	cmd := split[0]

	if argc > 1 {
		args = split[1:]
	}

	return cmd, args
}

func getCiliumPods(namespace, label string) ([]string, error) {
	output, err := execCommand("kubectl", "-n", namespace, "get", "pods", "-l", label)
	if err != nil {
		return nil, err
	}
	var ciliumPods []string

	lines := strings.Split(output, "\n")

	for _, l := range lines {
		if !strings.HasPrefix(l, "cilium") {
			continue
		}
		// NAME           READY     STATUS    RESTARTS   AGE
		// cilium-cfmww   0/1       Running   0          3m
		// ^
		pod := strings.Split(l, " ")[0]
		ciliumPods = append(ciliumPods, pod)
	}

	return ciliumPods, nil
}
