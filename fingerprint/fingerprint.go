package fingerprint

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Snapshot contains collected system fingerprint information.
type Snapshot struct {
	Hostname  string        `json:"hostname,omitempty"`
	OS        OSInfo        `json:"os"`
	MachineID string        `json:"machine_id,omitempty"`
	DMI       DMIInfo       `json:"dmi"`
	CPU       CPUInfo       `json:"cpu"`
	Memory    MemoryInfo    `json:"memory"`
	Network   []NetIf       `json:"network"`
	RootFS    RootFSInfo    `json:"rootfs"`
	Docker    DockerInfo    `json:"docker"`
	Runtime   GoRuntimeInfo `json:"go_runtime"`
}

// OSInfo represents operating system details.
type OSInfo struct {
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	KernelType string `json:"kernel_type,omitempty"`
	KernelRel  string `json:"kernel_release,omitempty"`
}

// DMIInfo holds DMI related data.
type DMIInfo struct {
	ProductUUID     string `json:"product_uuid,omitempty"`
	BoardSerial     string `json:"board_serial,omitempty"`
	ChassisAssetTag string `json:"chassis_asset_tag,omitempty"`
}

// CPUInfo describes CPU model information.
type CPUInfo struct {
	Model string `json:"model,omitempty"`
}

// MemoryInfo reports total memory in kilobytes.
type MemoryInfo struct {
	MemTotalKB uint64 `json:"mem_total_kb,omitempty"`
}

// NetIf contains network interface name and MAC address.
type NetIf struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

// RootFSInfo describes root filesystem source, type and UUID.
type RootFSInfo struct {
	Source string `json:"source,omitempty"`
	Fstype string `json:"fstype,omitempty"`
	UUID   string `json:"uuid,omitempty"`
}

// DockerInfo holds Docker daemon ID if available.
type DockerInfo struct {
	DaemonID string `json:"daemon_id,omitempty"`
}

// GoRuntimeInfo exposes GOOS and GOARCH.
type GoRuntimeInfo struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readOSEtc() (name, ver string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(ln, "NAME="), `"`)
		} else if strings.HasPrefix(ln, "VERSION=") {
			ver = strings.Trim(strings.TrimPrefix(ln, "VERSION="), `"`)
		}
	}
	return
}

func firstCPUModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		if strings.HasPrefix(ln, "model name") {
			parts := strings.SplitN(ln, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func memTotalKB() uint64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	var total uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		if strings.HasPrefix(ln, "MemTotal:") {
			var val uint64
			var unit string
			fmt.Sscanf(ln, "MemTotal: %d %s", &val, &unit)
			total = val
			break
		}
	}
	return total
}

func netIfaces() []NetIf {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []NetIf
	for _, it := range ifaces {
		if it.Name == "lo" {
			continue
		}
		mac := it.HardwareAddr.String()
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, NetIf{Name: it.Name, MAC: mac})
	}
	return out
}

func rootfsFromMountinfo() (source, fstype string) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		if !strings.Contains(ln, " - ") {
			continue
		}
		parts := strings.Split(ln, " - ")
		if len(parts) != 2 {
			continue
		}
		left := parts[0]
		right := parts[1]
		leftFields := strings.Fields(left)
		if len(leftFields) < 5 {
			continue
		}
		mountPoint := leftFields[4]
		if mountPoint != "/" {
			continue
		}
		rightFields := strings.Fields(right)
		if len(rightFields) >= 2 {
			fstype = rightFields[0]
			source = rightFields[1]
		}
		break
	}
	return
}

func dockerID() string {
	type daemonCfg struct {
		DataRoot string `json:"data-root"`
	}
	readFile := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	var roots []string
	if b, err := os.ReadFile("/etc/docker/daemon.json"); err == nil {
		var cfg daemonCfg
		if json.Unmarshal(b, &cfg) == nil && strings.TrimSpace(cfg.DataRoot) != "" {
			roots = append(roots, strings.TrimSpace(cfg.DataRoot))
		}
	}
	roots = append(roots,
		"/var/lib/docker",
		filepath.Join(os.Getenv("HOME"), ".local/share/docker"),
		"/var/snap/docker/common/var-lib-docker",
	)
	seen := map[string]struct{}{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		if id := readFile(filepath.Join(r, "engine-id")); id != "" {
			return id
		}
	}
	for _, p := range []string{"/var/lib/docker/.docker_id", "/var/lib/docker/.docker_uuid"} {
		if id := readFile(p); id != "" {
			return id
		}
	}
	if id := dockerIDViaUnixSocket(); id != "" {
		return id
	}
	if id := dockerIDViaCLI(); id != "" {
		return id
	}
	return ""
}

func dockerIDViaUnixSocket() string {
	type infoResp struct {
		ID string `json:"ID"`
	}
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial("unix", "/var/run/docker.sock")
	}
	tr := &http.Transport{DialContext: dialer}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", "http://unix/info", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var v infoResp
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return ""
	}
	return strings.TrimSpace(v.ID)
}

func dockerIDViaCLI() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "-f", "{{.ID}}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func ensureReadable(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func rootfsUUID(dev string) string {
	if dev == "" {
		return ""
	}
	realDev, err := filepath.EvalSymlinks(dev)
	if err != nil || realDev == "" {
		realDev = dev
	}
	const byUUID = "/dev/disk/by-uuid"
	if entries, err := os.ReadDir(byUUID); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			link := filepath.Join(byUUID, e.Name())
			target, err := os.Readlink(link)
			if err != nil {
				continue
			}
			fullTarget := target
			if !strings.HasPrefix(target, "/") {
				fullTarget = filepath.Join(byUUID, target)
			}
			resolved, err := filepath.EvalSymlinks(fullTarget)
			if err != nil {
				continue
			}
			if resolved == realDev {
				return e.Name()
			}
		}
	}
	out, err := exec.Command("blkid", "-s", "UUID", "-o", "value", dev).Output()
	if err == nil {
		if uuid := strings.TrimSpace(string(out)); uuid != "" {
			return uuid
		}
	}
	return ""
}

// GetSnapshot collects system information without producing any output.
func GetSnapshot() Snapshot {
	h, _ := os.Hostname()
	name, ver := readOSEtc()
	kType := readTrim("/proc/sys/kernel/ostype")
	kRel := readTrim("/proc/sys/kernel/osrelease")
	snap := Snapshot{
		Hostname: h,
		OS: OSInfo{
			Name:       name,
			Version:    ver,
			KernelType: kType,
			KernelRel:  kRel,
		},
		MachineID: readTrim("/etc/machine-id"),
		DMI: DMIInfo{
			ProductUUID:     readTrim("/sys/class/dmi/id/product_uuid"),
			BoardSerial:     readTrim("/sys/class/dmi/id/board_serial"),
			ChassisAssetTag: readTrim("/sys/class/dmi/id/chassis_asset_tag"),
		},
		CPU:     CPUInfo{Model: firstCPUModel()},
		Memory:  MemoryInfo{MemTotalKB: memTotalKB()},
		Network: netIfaces(),
		Runtime: GoRuntimeInfo{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
		Docker:  DockerInfo{DaemonID: dockerID()},
	}
	src, fstype := rootfsFromMountinfo()
	uuid := rootfsUUID(src)
	snap.RootFS = RootFSInfo{Source: src, Fstype: fstype, UUID: uuid}
	_ = filepath.WalkDir("/sys/class/dmi/id", func(path string, d fs.DirEntry, err error) error {
		return nil
	})
	return snap
}
