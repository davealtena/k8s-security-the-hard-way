# User Permissions and Security Contexts

In the previous section, you explored the Linux primitives that provide container isolation. Now you will see how Kubernetes Security Contexts map to these primitives to control who a container runs as and what privileges it has.

This guide covers:

* **User and group IDs** - Controlling the user identity of container processes
* **Linux capabilities** - Granting specific privileged operations without full root access
* **Privilege escalation** - Preventing processes from gaining additional privileges
* **Read-only filesystems** - Restricting write access to the container's root filesystem

You will configure these settings in pod specs and verify the underlying Linux configuration inside running containers.

## Prerequisites

Ensure your kind cluster is running:

```bash
kubectl get nodes
```

You should see two nodes in Ready status.

## Linux User IDs and Permissions

In Linux, every process runs with a User ID (UID). The UID is the kernel's primary access control mechanism. It defines ownership and determines what the process can access or modify.

By convention, UID 0 means root, which has full control over everything. UIDs 1-999 are usually reserved for system services. UIDs 1000 and above are assigned to regular users and applications.

Each time a process attempts a privileged operation, the Linux kernel checks its UID to decide whether that action should be allowed.

### Default Container Behavior

Most container images run as root by default. This happens because the image does not specify a user, so the container runtime defaults to UID 0.

Deploy a basic nginx container without any security context:

```bash
kubectl run nginx-default \
  --image=nginx:alpine \
  --restart=Never
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/nginx-default
```

Check which user the container process runs as:

```bash
kubectl exec nginx-default -- id
```

You should see:

```
uid=0(root) gid=0(root) groups=0(root)
```

The container runs as root. This is risky. If the container is compromised, the attacker gains root-level privileges over any accessible host resources.

Check which user owns the nginx process:

```bash
kubectl exec nginx-default -- ps aux
```

You should see:

```
PID   USER     TIME  COMMAND
    1 root      0:00 nginx: master process nginx -g daemon off;
    7 nginx     0:00 nginx: worker process
```

The master process runs as root. The worker processes run as the nginx user, which is a security improvement, but the master still has elevated privileges.

### Inspecting Users in Container Images

Many official images include non-root users, but do not use them by default. Inspect the nginx image:

```bash
kubectl exec nginx-default -- cat /etc/passwd | grep nginx
```

You should see:

```
nginx:x:101:101:nginx user:/nonexistent:/sbin/nologin
```

The nginx user exists with UID 101, but the container does not use it unless explicitly configured.

Let's check another popular image. Deploy a Node.js container:

```bash
kubectl run node-default \
  --image=node:20-slim \
  --restart=Never \
  -- sleep 3600
```

Wait for it to be ready:

```bash
kubectl wait --for=condition=ready pod/node-default
```

Check the runtime user:

```bash
kubectl exec node-default -- id
```

You should see:

```
uid=0(root) gid=0(root) groups=0(root)
```

Again, the container runs as root. Check if a non-root user exists:

```bash
kubectl exec node-default -- cat /etc/passwd | grep node
```

You should see:

```
node:x:1000:1000::/home/node:/bin/bash
```

The image defines a node user with UID 1000, but does not use it by default.

## Using runAsUser

Kubernetes provides the `runAsUser` field in the security context to explicitly set the UID for container processes. This overrides the image's default user.

Deploy a pod that runs as a non-root user:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-nonroot
spec:
  securityContext:
    runAsUser: 101
  containers:
  - name: nginx
    image: nginx:alpine
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/nginx-nonroot
```

Verify the user:

```bash
kubectl exec nginx-nonroot -- id
```

You should see:

```
uid=101(nginx) gid=0(root) groups=0(root)
```

The container now runs as UID 101, which corresponds to the nginx user. However, the process still belongs to the root group (GID 0). You can control the group using `runAsGroup`:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-usergroup
spec:
  securityContext:
    runAsUser: 101
    runAsGroup: 101
  containers:
  - name: nginx
    image: nginx:alpine
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/nginx-usergroup
```

Verify the user and group:

```bash
kubectl exec nginx-usergroup -- id
```

You should see:

```
uid=101(nginx) gid=101(nginx) groups=101(nginx)
```

Now the process runs with both the correct user and group.

## Using runAsNonRoot

Setting `runAsUser` to a specific UID is effective, but it requires knowing which UIDs exist in the image. You also need to ensure future image updates do not change the default back to root.

Kubernetes provides `runAsNonRoot` to enforce that the container never runs as UID 0, regardless of image defaults:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-nonroot-enforce
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: nginx
    image: nginx:alpine
EOF
```

Wait a moment and check the pod status:

```bash
kubectl get pod nginx-nonroot-enforce
```

You should see:

```
NAME                    READY   STATUS                       RESTARTS   AGE
nginx-nonroot-enforce   0/1     CreateContainerConfigError   0          5s
```

The pod fails to start. Check the events:

```bash
kubectl describe pod nginx-nonroot-enforce | tail -5
```

You should see an error message:

```
Error: container has runAsNonRoot and image will run as root (pod: "nginx-nonroot-enforce_default(...)", container: nginx)
```

Kubernetes blocks the container from starting because the image defaults to root and `runAsNonRoot` is set to true.

Combine both fields to enforce non-root execution and specify which user to use:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-safe
spec:
  securityContext:
    runAsUser: 101
    runAsNonRoot: true
  containers:
  - name: nginx
    image: nginx:alpine
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/nginx-safe
```

Verify the configuration:

```bash
kubectl exec nginx-safe -- id
```

You should see:

```
uid=101(nginx) gid=0(root) groups=0(root)
```

This configuration ensures the process runs as a specific non-root UID, and any future changes to the image or spec will not accidentally elevate privileges.

## Inspecting User Configuration from the Node

You can verify that the security context settings are enforced at the kernel level by inspecting the process from the host.

The pod runs on the worker node due to the control plane taint. Get a shell on the worker node:

```bash
docker exec -it security-demos-worker bash
```

Find the nginx process:

```bash
ps aux | grep "nginx: master" | grep -v grep
```

You should see output like:

```
101      12345  0.0  0.1  12345  6789 ?        Ss   12:00   0:00 nginx: master process nginx -g daemon off;
```

The first column shows the UID. The process runs as UID 101, confirming that Kubernetes applied the security context correctly.

Exit the node:

```bash
exit
```

## Linux Capabilities

Running as a non-root user significantly reduces risk, but some applications need to perform specific privileged operations. Rather than granting full root access, Linux capabilities let you grant fine-grained permissions.

Capabilities split root privileges into distinct units. For example, `CAP_CHOWN` allows changing file ownership, `CAP_NET_BIND_SERVICE` allows binding to privileged ports below 1024, and `CAP_SYS_PTRACE` allows tracing other processes.

### Dropping All Capabilities

By default, containers receive a set of capabilities even when running as non-root. Best practice is to drop all capabilities first, then add back only what is needed.

Deploy a pod that drops all capabilities:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: cap-drop-all
spec:
  containers:
  - name: app
    image: nicolaka/netshoot
    command: ["sleep", "3600"]
    securityContext:
      capabilities:
        drop: ["ALL"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/cap-drop-all
```

Check the capabilities:

```bash
kubectl exec cap-drop-all -- cat /proc/1/status | grep Cap
```

You should see:

```
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000000000000000
CapAmb: 0000000000000000
```

All capability bitmasks are zero. The process has no capabilities at all.

Most normal operations still work without any capabilities. Try making a network request:

```bash
kubectl exec cap-drop-all -- wget -q -O- https://example.com > /dev/null && echo "Success"
```

You should see:

```
Success
```

The request succeeds. Most applications do not need elevated privileges. However, certain operations require specific capabilities.

### Adding Specific Capabilities: Binding to Privileged Ports

In Linux, ports below 1024 are considered privileged. Only processes with `CAP_NET_BIND_SERVICE` can bind to these ports. This is why web servers often run as root or require special configuration.

Deploy nginx without any capabilities and try to bind to port 80:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-no-cap
spec:
  securityContext:
    runAsUser: 101
    runAsGroup: 101
    runAsNonRoot: true
  containers:
  - name: nginx
    image: nginx:alpine
    ports:
    - containerPort: 80
    securityContext:
      capabilities:
        drop: ["ALL"]
EOF
```

Wait a moment and check the pod status:

```bash
kubectl get pod nginx-no-cap
```

You should see:

```
NAME           READY   STATUS             RESTARTS     AGE
nginx-no-cap   0/1     CrashLoopBackOff   1 (5s ago)   10s
```

Check the logs:

```bash
kubectl logs nginx-no-cap
```

You should see an error like:

```
nginx: [emerg] bind() to 0.0.0.0:80 failed (13: Permission denied)
```

Nginx cannot bind to port 80 without the capability. Now add `CAP_NET_BIND_SERVICE`:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-with-cap
spec:
  securityContext:
    runAsUser: 101
    runAsGroup: 101
    runAsNonRoot: true
  containers:
  - name: nginx
    image: nginx:alpine
    ports:
    - containerPort: 80
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/nginx-with-cap
```

Verify nginx is running:

```bash
kubectl exec nginx-with-cap -- ps aux
```

You should see:

```
PID   USER     TIME  COMMAND
    1 nginx     0:00 nginx: master process nginx -g daemon off;
    7 nginx     0:00 nginx: worker process
```

Check the capabilities:

```bash
kubectl exec nginx-with-cap -- cat /proc/1/status | grep CapEff
```

You should see a non-zero value indicating the capability is present.

Test that nginx is actually serving on port 80:

```bash
kubectl exec nginx-with-cap -- wget -q -O- http://localhost | head -5
```

You should see HTML output from nginx's welcome page. The container now runs as a non-root user but can bind to privileged ports. This is exactly what production web servers need.

This demonstrates a common production pattern: run your web server as non-root, but grant only the specific capability needed to bind to standard HTTP ports.

### Adding Specific Capabilities: Network Administration

Some applications need to configure network interfaces or modify routing tables. This requires `CAP_NET_ADMIN`. Monitoring tools, VPN software, and network debugging utilities often need this capability.

Deploy a pod without `CAP_NET_ADMIN` and try to change network settings:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: netadmin-no-cap
spec:
  containers:
  - name: app
    image: nicolaka/netshoot
    command: ["sleep", "3600"]
    securityContext:
      capabilities:
        drop: ["ALL"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/netadmin-no-cap
```

Try to view network interfaces:

```bash
kubectl exec netadmin-no-cap -- ip link show
```

This works fine. Reading network configuration does not require capabilities. Now try to modify an interface:

```bash
kubectl exec netadmin-no-cap -- ip link set lo mtu 1400
```

You should see:

```
RTNETLINK answers: Operation not permitted
```

The operation fails because modifying network interfaces requires `CAP_NET_ADMIN`. Now deploy with the capability:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: netadmin-with-cap
spec:
  containers:
  - name: app
    image: nicolaka/netshoot
    command: ["sleep", "3600"]
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_ADMIN"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/netadmin-with-cap
```

Check the capabilities:

```bash
kubectl exec netadmin-with-cap -- cat /proc/1/status | grep CapEff
```

You should see a non-zero capability value.

Now try the same network modification:

```bash
kubectl exec netadmin-with-cap -- ip link set lo mtu 1400
```

This time it succeeds. Verify the change:

```bash
kubectl exec netadmin-with-cap -- ip link show lo | grep mtu
```

You should see:

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 1400 qdisc noqueue state UNKNOWN
```

The MTU changed to 1400. This capability is essential for network monitoring tools, VPNs, and infrastructure software that needs to configure network interfaces. However, it also grants significant control over networking, so it should only be used when necessary.

Verify that other privileged operations still fail:

```bash
kubectl exec netadmin-with-cap -- mount -t tmpfs tmpfs /mnt
```

You should see:

```
mount: /mnt: permission denied.
```

The mount operation requires `CAP_SYS_ADMIN`, which the container does not have. This demonstrates the principle of granting only the minimum capabilities needed.

## Preventing Privilege Escalation

Even when a container starts as a non-root user, it might attempt to gain more privileges during execution. This can happen through setuid binaries like `sudo` or `su`.

Kubernetes provides `allowPrivilegeEscalation` to prevent this. Setting it to false tells the container runtime to set the `no_new_privs` flag on the process at launch.

### Demonstrating Privilege Escalation

First, see what happens without the protection. Deploy a pod with sudo installed:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escalation-allowed
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: ubuntu:latest
    command: ["/bin/bash", "-c"]
    args:
    - |
      apt-get update -qq && apt-get install -y -qq sudo > /dev/null 2>&1
      echo "nobody ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/nobody
      su - nobody -s /bin/bash -c '
        echo "Current user: \$(whoami)"
        echo "Current UID: \$(id -u)"
        echo "Attempting sudo whoami..."
        sudo whoami
        echo "sudo exit status: \$?"
      '
    securityContext:
      allowPrivilegeEscalation: true
EOF
```

Wait for the pod to complete:

```bash
kubectl wait --for=condition=ready pod/escalation-allowed --timeout=60s
```

Check the logs:

```bash
kubectl logs escalation-allowed
```

You should see:

```
Current user: nobody
Current UID: 65534
Attempting sudo whoami...
root
sudo exit status: 0
```

The nobody user successfully escalated to root using sudo.

### Blocking Privilege Escalation

Now deploy the same setup with `allowPrivilegeEscalation: false`:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escalation-blocked
spec:
  restartPolicy: Never
  containers:
  - name: app
    image: ubuntu:latest
    command: ["/bin/bash", "-c"]
    args:
    - |
      apt-get update -qq && apt-get install -y -qq sudo > /dev/null 2>&1
      echo "nobody ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/nobody
      su - nobody -s /bin/bash -c '
        echo "Current user: \$(whoami)"
        echo "Current UID: \$(id -u)"
        echo "Attempting sudo whoami..."
        sudo whoami
        echo "sudo exit status: \$?"
      '
    securityContext:
      allowPrivilegeEscalation: false
EOF
```

Wait for the pod to complete:

```bash
kubectl wait --for=condition=ready pod/escalation-blocked --timeout=60s
```

Check the logs:

```bash
kubectl logs escalation-blocked
```

You should see:

```
Current user: nobody
Current UID: 65534
Attempting sudo whoami...
sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
sudo: If sudo is running in a container, you may need to adjust the container configuration to disable the flag.
sudo exit status: 1
```

The kernel blocks the privilege escalation attempt. Even though sudo is installed and configured, the `no_new_privs` flag prevents the process from gaining root privileges.

Verify the flag is set:

```bash
kubectl run test-no-new-privs \
  --image=alpine \
  --restart=Never \
  --rm \
  -it \
  --overrides='{"spec":{"containers":[{"name":"app","image":"alpine","command":["cat","/proc/1/status"],"securityContext":{"allowPrivilegeEscalation":false}}]}}' \
  | grep NoNewPrivs
```

You should see:

```
NoNewPrivs: 1
```

A value of 1 confirms the flag is active.

## Read-Only Root Filesystem

Most containers do not need to write to their own filesystem after startup. Allowing them to do so introduces unnecessary risk. If an attacker compromises the container, a writable root filesystem makes it easier to drop malicious binaries, overwrite scripts, or tamper with configuration files.

Kubernetes allows you to lock down the root filesystem using `readOnlyRootFilesystem`. This setting passes a read-only flag to the container runtime when mounting the root filesystem.

Deploy a pod with a read-only root filesystem:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: readonly-fs
spec:
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      readOnlyRootFilesystem: true
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/readonly-fs
```

Try to write to the root filesystem:

```bash
kubectl exec readonly-fs -- touch /test-file
```

You should see:

```
touch: /test-file: Read-only file system
```

The write operation fails. Try writing to a system directory:

```bash
kubectl exec readonly-fs -- touch /etc/test-file
```

You should see the same error:

```
touch: /etc/test-file: Read-only file system
```

The entire root filesystem is read-only. Verify this by checking the mount flags:

```bash
kubectl exec readonly-fs -- mount | grep "on / "
```

You should see:

```
overlay on / type overlay (ro,relatime,...)
```

The `ro` flag indicates the root filesystem is mounted read-only.

### Providing Writable Volumes

Some applications need to write logs to `/tmp`, store runtime state in `/var/run`, or generate temporary files. In these cases, mount writable volumes at those paths:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: readonly-with-tmp
spec:
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/readonly-with-tmp
```

Verify you cannot write to the root:

```bash
kubectl exec readonly-with-tmp -- touch /test-file
```

You should see:

```
touch: /test-file: Read-only file system
```

But you can write to the mounted volume:

```bash
kubectl exec readonly-with-tmp -- touch /tmp/test-file
```

Verify the file was created:

```bash
kubectl exec readonly-with-tmp -- ls -l /tmp/test-file
```

You should see:

```
-rw-r--r-- 1 root root 0 Oct 20 12:00 /tmp/test-file
```

This configuration keeps the rest of the filesystem immutable while providing a safe place to write.

## Combining Security Context Settings

The most secure configuration combines all these controls into a single pod spec:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 2000
    runAsNonRoot: true
    fsGroup: 2000
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/secure-pod
```

Verify the security settings:

```bash
kubectl exec secure-pod -- id
```

You should see:

```
uid=1000 gid=2000 groups=2000
```

Check capabilities:

```bash
kubectl exec secure-pod -- cat /proc/1/status | grep CapEff
```

You should see:

```
CapEff: 0000000000000000
```

Check the no_new_privs flag:

```bash
kubectl exec secure-pod -- cat /proc/1/status | grep NoNewPrivs
```

You should see:

```
NoNewPrivs: 1
```

Verify the root filesystem is read-only:

```bash
kubectl exec secure-pod -- touch /test-file
```

You should see:

```
touch: /test-file: Read-only file system
```

But writable volumes work:

```bash
kubectl exec secure-pod -- touch /tmp/test-file && echo "Success"
```

You should see:

```
Success
```

This pod runs as a non-root user, cannot elevate privileges, has no capabilities, and cannot modify its own filesystem. It represents a strong security baseline.

## Cleaning Up

Delete all demonstration pods:

```bash
kubectl delete pod nginx-default node-default nginx-nonroot nginx-nonroot-fixed \
  nginx-custom-group nginx-nonroot-enforce nginx-safe cap-drop-all \
  nginx-no-cap nginx-with-cap netadmin-no-cap netadmin-with-cap \
  escalation-allowed escalation-blocked readonly-fs readonly-with-tmp secure-pod \
  --force --grace-period=0
```

## Summary

You have seen how Kubernetes Security Contexts control container security at multiple layers:

* **runAsUser** sets the UID for container processes, overriding image defaults.
* **runAsNonRoot** enforces that containers never run as root, blocking pod creation if violated.
* **capabilities** let you grant specific privileged operations without full root access. Drop all capabilities first, then add only what is needed.
* **allowPrivilegeEscalation** prevents processes from gaining additional privileges through setuid binaries.
* **readOnlyRootFilesystem** makes the container's root filesystem immutable, preventing attackers from modifying binaries or configuration.

These settings map directly to Linux kernel features. The kubelet passes them to the container runtime, which configures the kernel accordingly. The kernel then enforces these restrictions for the lifetime of the process.

Security is not a single switch. It is a combination of controls that make it progressively harder for things to go wrong. Each setting blocks a specific class of attacks: privilege escalation, lateral movement, or persistence.

## Next Steps

In the next section, you will explore additional security mechanisms like seccomp profiles, fsGroup for volume permissions, and how to troubleshoot common security context failures.
