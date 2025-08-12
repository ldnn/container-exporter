项目说明
------------
本项目是一个基于 Go 语言编写的 Prometheus Exporter，用于收集并导出容器（如 Docker 或 containerd）的运行时信息。这些信息包括容器的名称、命名空间、镜像、IP 地址、MAC 地址和网络命名空间（netns）。主要用于检测容器环境中ip地址冲突的异常情况。

如找找到集群中ip相同，但是netns不同的条目

container_info and on(ip) (count by (ip) (count by (ip, netns) (container_info)) > 1)

功能特点
------------
支持从环境变量或系统主机名获取宿主机名称。

支持连接到 containerd 或 Docker 容器运行时。

支持获取容器的网络命名空间信息。

支持获取容器的 IP 地址和 MAC 地址。

支持通过 Prometheus 指标导出容器信息。

支持定期更新 Prometheus 指标。

使用方法
------------
编译并运行程序。

通过命令行参数指定 Prometheus 指标暴露的地址、容器运行时的 socket 路径、容器运行时类型（containerd 或 docker）以及 Docker API 版本。

访问指定的地址，即可获取 Prometheus 指标。

命令行参数
------------
-metrics-addr：Prometheus 指标暴露的地址，默认为 :9090。

-socket-path：容器运行时的 socket 路径，默认为 /var/run/containerd/containerd.sock。

-runtime：容器运行时类型，支持 containerd 或 docker，默认为 containerd。

-api-version：Docker API 版本，默认为 1.41。

注意事项
------------
确保程序有足够的权限访问容器运行时的 socket 文件和网络命名空间。

确保程序有足够的权限访问容器的网络接口信息。
