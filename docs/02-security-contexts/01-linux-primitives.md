# Linux Primitives Beneath Kubernetes

Before configuring security in Kubernetes, you need to understand what you are actually configuring. Kubernetes Security Contexts are declarative abstractions over Linux kernel features. Every setting in a pod spec maps to low-level kernel mechanisms that enforce isolation, resource limits, and access control.

This guide covers three fundamental Linux primitives that underpin container security:

* **System calls** - How processes interact with the kernel
* **Control groups** - How the kernel enforces resource limits
* **Namespaces** - How the kernel isolates what processes can see

You will deploy pods in your kind cluster and inspect these primitives directly. This hands-on approach builds intuition for how Kubernetes security works at the kernel level.

## Prerequisites

Create the cluster if you have not already:

```bash
kind create cluster --config kind-config.yaml
```

Verify the cluster is running:

```bash
kubectl get nodes
```

You should see two nodes in Ready status.

## System Calls: The Kernel's API

In Linux, user-space applications cannot interact with hardware or kernel-managed resources directly. Every interaction must go through the kernel via system calls.

System calls are predefined entry points that expose core kernel functionality. You can think of them as the kernel's API. There are over 300 system calls grouped by function: file operations, process management, networking, memory management.

Each system call has a unique ID and takes specific arguments. For example, the `open` syscall requires a file path, an access mode, and permission bits.

### Hands-On: Inspecting System Calls

Deploy a pod that includes debugging tools:

```bash
kubectl run syscall-demo \
  --image=nicolaka/netshoot \
  --restart=Never \
  -- sleep 3600
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/syscall-demo
```

Now trace system calls from a simple command. The `strace` utility intercepts and logs every syscall a process makes:

```bash
kubectl exec syscall-demo -- strace -e trace=openat ls /tmp 2>&1 | head -10
```

You should see output similar to:

```
openat(AT_FDCWD, "/tmp", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 3
```

Each line shows a syscall with its arguments and return value. The `openat` syscall opens files. The first argument is the directory file descriptor, the second is the path, and the third specifies flags like read-only mode.

The exact output may vary depending on which shared libraries are already loaded, but you will always see the `openat` syscall being used to access the `/tmp` directory.

Let's trace network-related syscalls:

```bash
kubectl exec syscall-demo -- strace -e trace=socket,connect curl -s http://httpbin.org/ip 2>&1 | grep -E "socket|connect"
```

You should see:

```
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 5
connect(5, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("54.204.39.132")}, 16) = 0
```

The `socket` syscall creates a TCP socket using IPv4. The `connect` syscall establishes the connection to the remote server. Even high-level operations like HTTP requests ultimately translate to these low-level kernel interactions.

### Why This Matters for Security

Every syscall is a potential attack surface. Privileged capabilities unlock groups of syscalls. For example, `CAP_NET_ADMIN` allows a process to modify routing tables, configure network interfaces, and manipulate iptables rules.

Two processes with the same capability can behave very differently depending on which syscalls they invoke. This is why syscall filtering through seccomp becomes important. You will explore that in later modules.

For now, understand that containers are just Linux processes. Every action they take goes through syscalls. Security mechanisms like capabilities and seccomp operate at this level.

## Control Groups: Enforcing Resource Limits

Control groups (cgroups) are kernel mechanisms that restrict how much CPU, memory, I/O, and other resources a process can consume. They define resource boundaries that the kernel enforces.

When Kubernetes sets resource limits on a pod, it creates cgroups and assigns the container processes to them. The kernel then ensures those processes cannot exceed the configured limits.

### Hands-On: Inspecting Control Groups

Deploy a pod with explicit resource limits:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: cgroup-demo
spec:
  containers:
  - name: app
    image: nginx:alpine
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
      requests:
        memory: "64Mi"
        cpu: "250m"
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/cgroup-demo
```

Check which cgroups the container process belongs to:

```bash
kubectl exec cgroup-demo -- cat /proc/1/cgroup
```

You should see output like:

```
0::/
```

This shows the container is using cgroup v2 (unified hierarchy). Modern Linux kernels use this simplified notation in `/proc/1/cgroup`. The full cgroup path is managed by the kubelet and container runtime.

To see the actual resource limits, inspect the cgroup filesystem directly. Check the memory limit enforced by the kernel:

```bash
kubectl exec cgroup-demo -- cat /sys/fs/cgroup/memory.max
```

You should see:

```
134217728
```

This is 128 MiB in bytes (128 * 1024 * 1024 = 134217728). The kernel will terminate the process if it attempts to allocate more memory than this limit.

Check the CPU limit:

```bash
kubectl exec cgroup-demo -- cat /sys/fs/cgroup/cpu.max
```

You should see something like:

```
50000 100000
```

This means the process can use 50000 microseconds of CPU time per 100000 microsecond period. That is 50% of one CPU core, which matches the 500m (500 millicores) limit.

### Inspecting from the Node

You can also inspect cgroups from the kind node itself. Remember that kind nodes are just Docker containers running Kubernetes components.

The control plane node has a taint that prevents workload pods from scheduling there. All demo pods run on the worker node. Get a shell in the worker node:

```bash
docker exec -it security-demos-worker bash
```

List all container memory limits in the burstable slice:

```bash
find /sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/ -path "*/cri-containerd-*.scope/memory.max" -exec sh -c 'echo "$1: $(cat $1)"' _ {} \;
```

You should see output with multiple containers. Look for the one with 134217728 bytes:

```
.../memory.max: 134217728
```

This is the cgroup-demo container. In cgroup v2, the full path structure looks like:

```
/sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<uuid>.slice/cri-containerd-<id>.scope/memory.max
```

The pod has resource limits but also requests, so it is classified as burstable QoS. The long UUIDs and container IDs are managed by Kubernetes and the container runtime.

Exit the node:

```bash
exit
```

### Why This Matters for Security

Cgroups prevent resource exhaustion attacks. Without limits, a compromised container could consume all available memory or CPU, affecting other workloads on the node.

However, cgroups only control how much a process can consume. They do not control what the process can see or interact with. That is where namespaces come in.

## Namespaces: Isolating What a Process Can See

While cgroups control resource consumption, namespaces control visibility. They determine which parts of the system a process can see and interact with.

Linux provides several namespace types:

* **PID namespace** - Process IDs are isolated; processes only see PIDs in their namespace
* **Network namespace** - Network interfaces, routing tables, and firewall rules are isolated
* **Mount namespace** - Filesystem mounts are isolated; processes see their own root filesystem
* **UTS namespace** - Hostname and domain name are isolated
* **IPC namespace** - Inter-process communication resources are isolated
* **User namespace** - User and group IDs are remapped between container and host
* **Cgroup namespace** - Cgroup root directory is isolated

### Hands-On: Inspecting Namespaces

List all namespaces on the control plane node:

```bash
docker exec security-demos-control-plane lsns
```

You should see output showing different namespace types:

```
        NS TYPE   NPROCS   PID USER COMMAND
4026531834 time      234     1 root /sbin/init
4026531835 cgroup    234     1 root /sbin/init
4026531836 pid       234     1 root /sbin/init
4026531837 user      234     1 root /sbin/init
4026531838 uts       234     1 root /sbin/init
4026531839 ipc       234     1 root /sbin/init
4026531840 net       234     1 root /sbin/init
4026531841 mnt       234     1 root /sbin/init
```

Each namespace has a unique ID. Processes in different namespaces have different views of the system.

Deploy a pod to inspect its namespaces:

```bash
kubectl run namespace-demo \
  --image=nicolaka/netshoot \
  --restart=Never \
  -- sleep 3600
```

Wait for it to be ready:

```bash
kubectl wait --for=condition=ready pod/namespace-demo
```

Check which namespaces the container process belongs to:

```bash
kubectl exec namespace-demo -- ls -l /proc/1/ns
```

You should see:

```
lrwxrwxrwx 1 root root 0 Jan 15 12:00 cgroup -> 'cgroup:[4026532842]'
lrwxrwxrwx 1 root root 0 Jan 15 12:00 ipc -> 'ipc:[4026532840]'
lrwxrwxrwx 1 root root 0 Jan 15 12:00 mnt -> 'mnt:[4026532838]'
lrwxrwxrwx 1 root root 0 Jan 15 12:00 net -> 'net:[4026532843]'
lrwxrwxrwx 1 root root 0 Jan 15 12:00 pid -> 'pid:[4026532841]'
lrwxrwxrwx 1 root root 0 Jan 15 12:00 uts -> 'uts:[4026532839]'
```

Each symlink points to a namespace ID. These IDs differ from the host, confirming the container is isolated.

### PID Namespace Isolation

In a PID namespace, the process sees only other processes in the same namespace:

```bash
kubectl exec namespace-demo -- ps aux
```

You should see:

```
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.0   2888  1024 ?        Ss   12:00   0:00 sleep 3600
root        12  0.0  0.0   7640  3328 ?        Rs   12:01   0:00 ps aux
```

The container sees itself as PID 1. It cannot see any other processes on the host.

Compare this to the host view. The pod runs on the worker node due to the control plane taint. Exec into the worker node:

```bash
docker exec security-demos-worker ps aux | grep sleep | head -5
```

You will see the same sleep process but with a different PID from the host's perspective.

### Network Namespace Isolation

Check the network interfaces visible to the container:

```bash
kubectl exec namespace-demo -- ip addr
```

You should see something like:

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
3: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    inet 10.244.0.5/24 brd 10.244.0.255 scope global eth0
```

The container has its own loopback and a virtual ethernet interface. It does not see the host's network interfaces directly.

### Mount Namespace Isolation

The container has its own view of the filesystem:

```bash
kubectl exec namespace-demo -- df -h
```

You should see:

```
Filesystem      Size  Used Avail Use% Mounted on
overlay          59G  8.2G   48G  15% /
tmpfs            64M     0   64M   0% /dev
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
```

The root filesystem is an overlay. The container does not see the host's full filesystem tree.

### Why This Matters for Security

Namespaces provide the foundation for container isolation. Without them, containers would see all processes, network interfaces, and filesystems on the host.

However, namespaces alone do not prevent privilege escalation. A process can still have dangerous capabilities or run as root within its namespace. That is why you layer additional controls like user IDs, capabilities, and seccomp profiles.

## Cleaning Up

Delete the demonstration pods:

```bash
kubectl delete pod syscall-demo cgroup-demo namespace-demo --force --grace-period=0
```

## Summary

You have seen how Linux primitives work at the kernel level:

* **System calls** are the interface between user-space processes and the kernel. Every container action goes through syscalls.
* **Control groups** enforce resource limits. Kubernetes resource limits translate to cgroup settings that the kernel enforces.
* **Namespaces** isolate what processes can see. Containers get their own PID, network, and mount namespaces.

These primitives are not Kubernetes-specific. They are Linux kernel features. Docker, Podman, and other container runtimes use the same mechanisms. Kubernetes just provides a declarative API on top of them.

In the next section, you will see how Kubernetes Security Contexts map to these primitives. You will configure user IDs, capabilities, and filesystem permissions using the Kubernetes API, and then verify the underlying Linux configuration.

## Next Steps

Proceed to [User Permissions and Security Contexts](02-user-permissions.md) to see how Kubernetes controls who a container runs as and what privileges it has.
