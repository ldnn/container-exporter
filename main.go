package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/filters"
	"github.com/moby/moby/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// 创建一个容器指标
var (
	containerInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "container_info",
			Help: "Container Info including name, namespace, image, netns, IP and MAC address",
		},
		[]string{"node", "container", "namespace", "pod", "ip", "mac", "image", "netns"},
	)

	apiVersion string // Docker API version
)

func init() {
	// 注册指标
	prometheus.MustRegister(containerInfo)
}

// 获取宿主机名称
func getHostName() string {
	hostname := os.Getenv("NODE_HOSTNAME")
	if hostname == "" {
		// 如果环境变量为空，尝试获取系统主机名作为备用
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			log.Printf("Error getting hostname from both environment and system: %v", err)
			return "unknown"
		}
		log.Printf("Using system hostname: %s", hostname)
	}
	return hostname
}

// 获取宿主机上所有容器的名称、命名空间、IP 地址、MAC 地址并更新 Prometheus 指标
func inspectAllContainersContainerd(socketPath string) {

	// 获取宿主机名称
	hostName := getHostName()

	// 连接到 containerd

	socket := "/host" + socketPath
	client, err := containerd.New(socket)
	if err != nil {
		log.Fatalf("Error connecting to containerd: %v", err)
	}
	defer client.Close()

	// 设置命名空间，k8s.io 是 Kubernetes 默认的 namespace
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	// 获取宿主机上所有的容器
	containers, err := client.Containers(ctx)
	if err != nil {
		log.Printf("Error getting containers: %v", err)
		return
	}

	// 保存当前的 netns
	origNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatalf("error opening current netns: %v", err)
	}

	// 遍历每个容器并获取详细信息
	for _, c := range containers {
		container, err := c.Info(ctx)
		if err != nil {
			log.Printf("Error getting container info for container %s: %v", c.ID(), err)
			continue
		}
		containerID := container.ID
		labels := container.Labels
		containerName := labels["io.kubernetes.container.name"]
		namespace := labels["io.kubernetes.pod.namespace"]
		podName := labels["io.kubernetes.pod.name"]
		image := container.Image

		// 获取容器的任务信息
		task, err := c.Task(ctx, nil)
		if err != nil {
			log.Printf("Error getting task for container %s: %v", containerID, err)
			continue
		}

		// 获取容器的 PID
		pid := fmt.Sprintf("%d", task.Pid())

		ipAddress, macAddress, netns, err := GetContainerNetInfo(pid, origNS)
		if err != nil {
			log.Printf("%s: %v", containerName, err)
		}
		// 更新 Prometheus 指标，包括宿主机名、容器名、命名空间、Pod名、IP 和 MAC 地址
		containerInfo.WithLabelValues(hostName, containerName, namespace, podName, ipAddress, macAddress, image, netns).Set(1)

	}
	origNS.Close()
}

func inspectAllContainersDocker(socketPath string) {
	// 创建 Docker 客户端
	var (
		podName   string
		namespace string
	)

	// 获取宿主机名称
	hostName := getHostName()

	socket := "unix:///host" + socketPath

	cli, err := client.NewClientWithOpts(
		client.WithHost(socket),
		client.WithVersion(apiVersion),
	)
	if err != nil {
		log.Fatalf("Error creating Docker client: %v", err)
	}

	// 获取所有容器的信息
	containers, err := cli.ContainerList(context.Background(), container.ListOptions{
		All:     false,
		Filters: filters.NewArgs(),
	})

	if err != nil {
		log.Fatalf("Error getting container list: %v", err)
	}

	// 保存当前的 netns
	origNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		log.Fatalf("error opening current netns: %v", err)
	}

	// 遍历所有容器并获取容器的名称和 PID
	for _, container := range containers {
		containerdSpec, err := cli.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			log.Printf("Error inspecting container %s: %v", container.ID, err)
			continue
		}

		// 输出容器的名称和 PID
		containerName := strings.TrimPrefix(containerdSpec.Name, "/")
		pid := fmt.Sprintf("%d", containerdSpec.State.Pid)
		image := containerdSpec.Config.Image

		ipAddress, macAddress, netns, err := GetContainerNetInfo(pid, origNS)
		if err != nil {
			log.Printf("%s: %v", containerName, err)
		}
		// 更新 Prometheus 指标，包括宿主机名、容器名、命名空间、Pod名、IP 和 MAC 地址
		containerInfo.WithLabelValues(hostName, containerName, namespace, podName, ipAddress, macAddress, image, netns).Set(1)

	}

	origNS.Close()

}

func GetContainerNetInfo(pid string, origNS *os.File) (ip, mac, netns string, err error) {
	// 获取容器的网络命名空间
	nsPath := fmt.Sprintf("/host/proc/%v/ns/net", pid)
	ns, err := os.Open(nsPath)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read netns: %w", err)
	}
	defer ns.Close()
	// 获取netns
	fi, err := ns.Stat()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read netns: %w", err)
	}
	stat := fi.Sys().(*syscall.Stat_t)
	netns = fmt.Sprintf("%d", stat.Ino)

	// 切换到容器的网络命名空间
	err = unix.Setns(int(ns.Fd()), unix.CLONE_NEWNET)
	if err != nil {
		return "", "", "", fmt.Errorf("error setting network namespace for container %v", err)
	}

	// 获取容器的 IP 地址和 MAC 地址
	ipAddress, macAddress := getContainerNetLinkInfo()
	if ipAddress == "" {
		return "", "", "", fmt.Errorf("error getting IP Address for container")
	}
	if macAddress == "" {
		return "", "", "", fmt.Errorf("error getting MAC Address for container")
	}

	// 切回 netns
	if err := unix.Setns(int(origNS.Fd()), unix.CLONE_NEWNET); err != nil {
		log.Printf("error restoring original netns: %v", err)
	}
	return ipAddress, macAddress, netns, nil
}

// 获取容器的 IP 地址和 MAC 地址
func getContainerNetLinkInfo() (string, string) {
	// 获取网络接口信息
	links, err := netlink.LinkList()
	if err != nil {
		log.Printf("error getting network interfaces: %v", err)
		return "", ""
	}

	// 查找容器的网络接口（通常是 eth0）
	for _, link := range links {
		if link.Attrs().Name == "eth0" {
			// 获取 IP 地址
			addrs, err := netlink.AddrList(link, unix.AF_INET)
			if err != nil {
				log.Printf("error getting addresses: %v", err)
				return "", ""
			}

			// 返回容器的第一个 IP 地址
			if len(addrs) > 0 {
				// 获取 MAC 地址
				macAddress := link.Attrs().HardwareAddr.String()
				return addrs[0].IP.String(), macAddress
			}
		}
	}

	return "", ""
}

// 启动 Prometheus exporter HTTP 服务
func startExporter(metricsAddr string) {
	fmt.Printf("Starting Prometheus exporter on %v", metricsAddr)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Prometheus exporter is running. Access /metrics for metrics.\n")
	})
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(metricsAddr, nil)
	if err != nil {
		log.Fatalf("Error starting HTTP server: %v", err)
	}
}

// dockerContainer 处理 Docker 容器名称，提取 Pod 名称和命名空间
// 如果容器名称不符合预期格式，则返回空字符串
// 如果是由 Docker 直接管理的容器，则打印相关信息并返回空字符串
// 如果容器名称符合预期格式，则提取 Pod 名称和命名空间并返回
// 返回值：podName, namespace
// 示例：输入 "k8s_containerName_podName_namespace_"，输出 podName 和 namespace
// 示例：输入 "docker_containerName" 或其他非预期格式，输出空字符串
func dockerContainer(containerName string) (podName string, namespace string) {

	// 编译正则表达式
	re := regexp.MustCompile(`^/k8s_.*_.*_.*_$`)

	// 检查字符串是否匹配模式
	if re.MatchString(containerName) {
		// 使用 _ 分割字符串
		parts := strings.Split(containerName, "_")

		// 输出分割结果
		if len(parts) >= 4 {
			podName = parts[2]
			namespace = parts[3]
			fmt.Printf("Pod Name: %s, Namespace: %s\n", podName, namespace)
			return podName, namespace
		} else {
			fmt.Println("Container name does not match expected format.")
			return "", ""
		}
	} else {
		fmt.Printf("%v: 由docker直接管理的容器\n", containerName)
		return "", ""
	}
}

// 获取容器信息并更新 Prometheus 指标
func inspectAllContainers(socketPath string, runtime string) {
	if runtime == "containerd" {
		inspectAllContainersContainerd(socketPath)
	} else if runtime == "docker" {
		inspectAllContainersDocker(socketPath)
	} else {
		log.Fatalf("Unsupported runtime: %s", runtime)
	}
}

func main() {
	var metricsAddr string
	var socketPath string
	var runtime string

	// 解析命令行参数
	flag.StringVar(&metricsAddr, "metrics-addr", ":9090", "Address to expose metrics")
	flag.StringVar(&socketPath, "socket-path", "/var/run/containerd/containerd.sock", "Path to containerd socket")
	flag.StringVar(&runtime, "runtime", "containerd", "Container runtime (containerd or docker)")
	flag.StringVar(&apiVersion, "api-version", "1.41", "Docker API version")
	flag.Parse()

	// 定期每 15 秒更新一次指标
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// 启动 HTTP 服务来提供指标
	go startExporter(metricsAddr)

	for range ticker.C {
		// 获取容器信息并更新 Prometheus 指标
		containerInfo.Reset() // 重置指标
		inspectAllContainers(socketPath, runtime)
	}

}
