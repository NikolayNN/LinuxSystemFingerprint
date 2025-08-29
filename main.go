package main

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

type OSInfo struct {
	Name       string `json:"name,omitempty"`           // NAME из /etc/os-release
	Version    string `json:"version,omitempty"`        // VERSION из /etc/os-release
	KernelType string `json:"kernel_type,omitempty"`    // /proc/sys/kernel/ostype (обычно "Linux")
	KernelRel  string `json:"kernel_release,omitempty"` // /proc/sys/kernel/osrelease
}

type DMIInfo struct {
	ProductUUID     string `json:"product_uuid,omitempty"`      // /sys/class/dmi/id/product_uuid
	BoardSerial     string `json:"board_serial,omitempty"`      // /sys/class/dmi/id/board_serial
	ChassisAssetTag string `json:"chassis_asset_tag,omitempty"` // /sys/class/dmi/id/chassis_asset_tag
}

type CPUInfo struct {
	Model string `json:"model,omitempty"` // первый "model name" из /proc/cpuinfo
}

type MemoryInfo struct {
	MemTotalKB uint64 `json:"mem_total_kb,omitempty"` // MemTotal из /proc/meminfo
}

type NetIf struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
}

type RootFSInfo struct {
	Source string `json:"source,omitempty"` // устройство/источник для /
	Fstype string `json:"fstype,omitempty"` // из mountinfo
	UUID   string `json:"uuid,omitempty"`   // UUID файловой системы корня
}

type DockerInfo struct {
	DaemonID string `json:"daemon_id,omitempty"` // /var/lib/docker/.docker_id или .docker_uuid
}

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
			total = val // в KB
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
	// Формат: id parent major:minor root mount_point options - fstype source superopts
	// Ищем строку с mount_point " / "
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		// грубо проверим " / " с пробелами для уменьшения ложных
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
		// mount_point — 5-е поле слева (после id, parent, major:minor, root)
		if len(leftFields) < 5 {
			continue
		}
		mountPoint := leftFields[4]
		if mountPoint != "/" {
			continue
		}
		rightFields := strings.Fields(right)
		// right: fstype source superopts
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

	// 1) Путь через data-root
	var roots []string
	if b, err := os.ReadFile("/etc/docker/daemon.json"); err == nil {
		var cfg daemonCfg
		if json.Unmarshal(b, &cfg) == nil && strings.TrimSpace(cfg.DataRoot) != "" {
			roots = append(roots, strings.TrimSpace(cfg.DataRoot))
		}
	}
	roots = append(roots,
		"/var/lib/docker", // стандарт
		filepath.Join(os.Getenv("HOME"), ".local/share/docker"), // rootless
		"/var/snap/docker/common/var-lib-docker",                // snap
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
	// старые/кастомные варианты (на всякий случай)
	for _, p := range []string{"/var/lib/docker/.docker_id", "/var/lib/docker/.docker_uuid"} {
		if id := readFile(p); id != "" {
			return id
		}
	}

	// 2) Попытка через Docker API по unix-сокету: GET /info -> .ID
	if id := dockerIDViaUnixSocket(); id != "" {
		return id
	}

	// 3) Фолбэк: docker CLI (если доступен бинарь и сокет)
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
	tr := &http.Transport{
		DialContext: dialer,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   2 * time.Second,
	}
	// адрес может быть любым http://host — важен только путь и сокет
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

	// Нормализуем путь устройства (разрешаем все ссылки)
	realDev, err := filepath.EvalSymlinks(dev)
	if err != nil || realDev == "" {
		realDev = dev
	}

	// 1) Попытка через /dev/disk/by-uuid (без внешних команд)
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
			// target может быть относительным путём вида ../../dm-0
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

	// 2) Фолбэк: blkid (если доступен)
	out, err := exec.Command("blkid", "-s", "UUID", "-o", "value", dev).Output()
	if err == nil {
		if uuid := strings.TrimSpace(string(out)); uuid != "" {
			return uuid
		}
	}

	return ""
}

func main() {
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
		CPU: CPUInfo{
			Model: firstCPUModel(),
		},
		Memory: MemoryInfo{
			MemTotalKB: memTotalKB(),
		},
		Network: netIfaces(),
		Runtime: GoRuntimeInfo{
			GOOS:   runtime.GOOS,
			GOARCH: runtime.GOARCH,
		},
		Docker: DockerInfo{
			DaemonID: dockerID(),
		},
	}

	src, fstype := rootfsFromMountinfo()

	uuid := rootfsUUID(src)
	snap.RootFS = RootFSInfo{Source: src, Fstype: fstype, UUID: uuid}

	// подсказка по доступности путей (удобно при отладке прав)
	_ = filepath.WalkDir("/sys/class/dmi/id", func(path string, d fs.DirEntry, err error) error {
		// ничего не делаем; просто избирательно проверили существование ранее
		return nil
	})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		fmt.Fprintln(os.Stderr, "encode error:", err)
		os.Exit(1)
	}

}
