# Advanced Security Contexts

In the previous section, you learned how to control user permissions, capabilities, and filesystem access using Security Contexts. These are essential building blocks, but production workloads need additional layers of defense.

This guide covers advanced security mechanisms that further restrict what containers can do:

* **fsGroup and supplementary groups** - Managing file permissions for volumes shared across containers
* **seccomp profiles** - Filtering which system calls containers can invoke
* **AppArmor profiles** - Enforcing mandatory access control policies
* **SELinux contexts** - Alternative MAC system used in Red Hat environments
* **Troubleshooting security contexts** - Diagnosing and fixing common configuration issues

These features build on the Linux primitives you explored earlier. Each adds a distinct security layer that makes exploitation progressively harder.

## Prerequisites

Ensure your kind cluster is running:

```bash
kubectl get nodes
```

You should see two nodes in Ready status.

## File System Group and Volume Permissions

Containers often need to share persistent volumes. When multiple containers write to the same volume, file ownership and permissions become critical. Without proper configuration, one container might not be able to read files created by another.

The `fsGroup` field tells Kubernetes to apply a specific group ID to all files in mounted volumes. This happens at mount time. The kubelet instructs the container runtime to recursively chown the volume directory, setting the group ownership to the specified GID.

### The Problem: Default Volume Permissions

When multiple containers in a pod need to share files on a volume, file ownership and permissions become critical. Without proper configuration, containers running as different users might not be able to access each other's files.

Deploy a pod with two containers that share a volume without fsGroup:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: volume-permission-problem
spec:
  containers:
  - name: writer
    image: alpine
    command: ["sh", "-c"]
    args:
    - |
      echo "restricted data" > /data/restricted.txt
      chmod 640 /data/restricted.txt
      echo "Writer created file with permissions:"
      ls -l /data/restricted.txt
      sleep 3600
    securityContext:
      runAsUser: 1000
      runAsGroup: 2000
    volumeMounts:
    - name: shared-data
      mountPath: /data
  - name: reader
    image: alpine
    command: ["sh", "-c"]
    args:
    - |
      sleep 5
      echo "Reader attempting to read file:"
      cat /data/restricted.txt || echo "Permission denied - cannot read file"
      sleep 3600
    securityContext:
      runAsUser: 1001
      runAsGroup: 3000
    volumeMounts:
    - name: shared-data
      mountPath: /data
  volumes:
  - name: shared-data
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/volume-permission-problem
```

Check the writer's output:

```bash
kubectl logs volume-permission-problem -c writer
```

You should see:

```
Writer created file with permissions:
-rw-r----- 1 1000 2000 15 Oct 29 12:00 /data/restricted.txt
```

The file is owned by UID 1000 and GID 2000, with 640 permissions (readable only by owner and group members). Now check the reader's output:

```bash
kubectl logs volume-permission-problem -c reader
```

You should see:

```
Reader attempting to read file:
Permission denied - cannot read file
```

The reader container runs as UID 1001 with GID 3000. It is neither the file owner nor a member of group 2000, so it cannot read the file.

Verify the reader's identity:

```bash
kubectl exec volume-permission-problem -c reader -- id
```

You should see:

```
uid=1001 gid=3000 groups=3000
```

This is a common problem when multiple containers need to collaborate on shared storage. Each container writes files owned by its own UID and GID, making cross-container access difficult.


### The Solution: Using fsGroup

The fsGroup field solves this problem by ensuring all containers in the pod share the same supplementary group. Files created on the volume inherit this group ownership.

Delete the test pod:

```bash
kubectl delete pod volume-permission-problem --grace-period=0 --force
```

Deploy a pod with fsGroup configured:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: shared-volume-pod
spec:
  securityContext:
    fsGroup: 5000
  containers:
  - name: writer
    image: alpine
    command: ["sh", "-c"]
    args:
    - |
      echo "Directory permissions:"
      ls -ld /data
      echo "shared data" > /data/shared.txt
      chmod 660 /data/shared.txt
      echo "File created with permissions:"
      ls -l /data/shared.txt
      sleep 3600
    securityContext:
      runAsUser: 1000
    volumeMounts:
    - name: shared-data
      mountPath: /data
  - name: reader
    image: alpine
    command: ["sh", "-c"]
    args:
    - |
      sleep 10
      echo "Reader's identity:"
      id
      echo "Attempting to read file:"
      cat /data/shared.txt
      sleep 3600
    securityContext:
      runAsUser: 1001
    volumeMounts:
    - name: shared-data
      mountPath: /data
  volumes:
  - name: shared-data
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/shared-volume-pod
```

Check the writer's output:

```bash
kubectl logs shared-volume-pod -c writer
```

You should see:

```
Directory permissions:
drwxrwsrwx 2 root 5000 40 Oct 29 19:50 /data
File created with permissions:
-rw-rw---- 1 1000 5000 12 Oct 29 19:50 /data/shared.txt
```

Notice two important things. First, the directory has group ownership of 5000 (the fsGroup) and has the setgid bit set (the `s` in `rws`). Second, the file created by the writer inherited the group ownership of 5000 from the directory, not from the container's primary GID.

This happens because the setgid bit on the directory causes new files to inherit the directory's group ownership. Check that the reader can access it:

```bash
kubectl logs shared-volume-pod -c reader
```

You should see:

```
Reader's identity:
uid=1001 gid=0(root) groups=0(root),5000
Attempting to read file:
shared data
```

The reader successfully accessed the file. Notice that the reader belongs to supplementary group 5000, even though its primary GID is 0 (because we didn't set runAsGroup, it defaults to root's GID). This supplementary group membership grants access to files owned by group 5000.

You can verify both containers have the fsGroup as a supplementary group:


### How fsGroup Works at the Kernel Level

The fsGroup setting triggers three important actions when the volume mounts:

First, the kubelet sets the group ownership of the volume directory itself to the specified GID. Second, it sets the setgid bit on the directory. This combination causes any new files created in the directory to inherit the directory's group ownership rather than the creating process's primary GID.

Third, Kubernetes adds the fsGroup as a supplementary group to the security context of every container in the pod. This means even if a container runs as a different primary GID (or no specific runAsGroup is set), it still belongs to the fsGroup for permission checks.

You can verify this by checking the volume directory on the node. Get a shell on the worker node:

```bash
docker exec -it security-demos-worker bash
```

Find the volume mount path. It will be under `/var/lib/kubelet/pods`:

```bash
find /var/lib/kubelet/pods -name shared-data -type d 2>/dev/null | head -1
```

Check the directory permissions:

```bash
ls -ld $(find /var/lib/kubelet/pods -name shared-data -type d 2>/dev/null | head -1)
```

You should see:

```
drwxrwsrwx 2 root 5000 40 Oct 29 19:50 /var/lib/kubelet/pods/.../shared-data
```

Notice the group ownership is 5000 and the setgid bit is set (the `s` in `rws`). List the files:

```bash
ls -l $(find /var/lib/kubelet/pods -name shared-data -type d 2>/dev/null | head -1)
```

You should see files with GID 5000, inherited from the directory through the setgid mechanism.

Exit the node:

```bash
exit
```

The combination of setting the directory's group ownership, enabling the setgid bit, and adding fsGroup as a supplementary group to all containers ensures that all containers can read and write files on the shared volume. Files inherit the shared group through the setgid directory, and all containers have permission to access those files through their supplementary group membership.

### fsGroupChangePolicy

By default, Kubernetes recursively changes ownership of all existing files in the volume every time it mounts. For large persistent volumes with many files, this can slow down pod startup significantly.

The `fsGroupChangePolicy` field controls this behavior:

* `Always` - Change ownership on every mount (default)
* `OnRootMismatch` - Only change ownership if the root directory does not match the expected GID

Deploy a pod with the optimized policy:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: fsgroup-optimized
spec:
  securityContext:
    fsGroup: 6000
    fsGroupChangePolicy: OnRootMismatch
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/fsgroup-optimized
```

Check the volume permissions:

```bash
kubectl exec fsgroup-optimized -- ls -ld /data
```

You should see:

```
drwxrwsrwx 2 root 6000 40 Oct 29 12:00 /data
```

The directory has the correct group ownership. The `s` bit in the permissions (shown in `rws`) indicates the setgid bit is set. This means new files created in this directory automatically inherit the directory's group ownership.

For persistent volumes that already have correct ownership from a previous mount, `OnRootMismatch` skips the recursive chown and speeds up pod restarts.

## Seccomp Profiles: Filtering System Calls

In the Linux Primitives section, you learned that every container action translates to system calls. Containers rarely need all 300+ available syscalls. Restricting which syscalls a container can invoke reduces the attack surface significantly.

Seccomp (secure computing mode) is a Linux kernel feature that filters syscalls. You define an allowed or denied list of syscalls, and the kernel blocks any attempt to invoke syscalls outside the policy.

Kubernetes supports three seccomp profile types:

* `RuntimeDefault` - Uses the container runtime's default profile, which blocks dangerous syscalls
* `Unconfined` - Allows all syscalls (no filtering)
* `Localhost` - Loads a custom profile from a file on the node

### The Default: No Seccomp Profile

Before Kubernetes 1.22, pods ran without seccomp filtering by default. This meant containers could invoke any syscall. Deploy a pod without an explicit seccomp profile:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-seccomp
spec:
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/no-seccomp
```

Check the seccomp status:

```bash
kubectl exec no-seccomp -- cat /proc/1/status | grep Seccomp
```

You should see:

```
Seccomp: 0
```

A value of 0 means seccomp is disabled. The container can invoke any syscall.

In Kubernetes 1.22 and later, the default changed to `RuntimeDefault` in most distributions, but it is worth explicitly setting it to avoid surprises.

### Using RuntimeDefault Profile

The RuntimeDefault profile blocks syscalls that are rarely needed and often associated with exploits. This includes syscalls for kernel module loading, system time modification, and some privileged operations.

Deploy a pod with the RuntimeDefault profile:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-runtime-default
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/seccomp-runtime-default
```

Check the seccomp status:

```bash
kubectl exec seccomp-runtime-default -- cat /proc/1/status | grep Seccomp
```

You should see:

```
Seccomp: 2
```

A value of 2 means seccomp is active in filter mode. The container can only invoke syscalls permitted by the profile.

Most applications work fine with RuntimeDefault. Try some common operations:

```bash
kubectl exec seccomp-runtime-default -- ls /
kubectl exec seccomp-runtime-default -- wget -q -O- https://example.com > /dev/null && echo "Success"
kubectl exec seccomp-runtime-default -- ps aux
```

All these commands succeed. Now try a syscall that is typically blocked:

```bash
kubectl exec seccomp-runtime-default -- sh -c 'date -s "2025-01-01 00:00:00"'
```

You should see:

```
date: can't set date: Operation not permitted
```

The `clock_settime` syscall is blocked by the RuntimeDefault profile. This prevents containers from modifying the system clock, which could interfere with time-based security mechanisms or logging.

### Creating a Custom Seccomp Profile

For high-security environments, you can create custom profiles that allow only the specific syscalls your application needs. This follows the principle of least privilege at the syscall level.

However, creating truly minimal seccomp profiles is extremely challenging. Even basic container initialization requires dozens of syscalls that the container runtime (runc/containerd) needs before your application even starts. A profile that is too restrictive will prevent the container from starting at all.

Custom profiles are JSON files that list allowed or denied syscalls. You place these files on each node, and Kubernetes loads them when starting the container.

First, get a shell on the worker node:

```bash
docker exec -it security-demos-worker bash
```

Create a directory for seccomp profiles:

```bash
mkdir -p /var/lib/kubelet/seccomp
```

Create a profile that blocks specific dangerous syscalls while allowing most others:

```bash
cat > /var/lib/kubelet/seccomp/restricted.json <<'EOF'
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "acct",
        "add_key",
        "bpf",
        "clock_adjtime",
        "clock_settime",
        "delete_module",
        "finit_module",
        "init_module",
        "ioperm",
        "iopl",
        "kcmp",
        "kexec_file_load",
        "kexec_load",
        "keyctl",
        "lookup_dcookie",
        "mount",
        "move_pages",
        "name_to_handle_at",
        "open_by_handle_at",
        "perf_event_open",
        "personality",
        "pivot_root",
        "process_vm_readv",
        "process_vm_writev",
        "ptrace",
        "reboot",
        "request_key",
        "set_mempolicy",
        "setns",
        "settimeofday",
        "stime",
        "swapon",
        "swapoff",
        "syslog",
        "umount",
        "umount2",
        "unshare",
        "uselib",
        "userfaultfd",
        "ustat",
        "vm86",
        "vm86old"
      ],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
EOF
```

Exit the node:

```bash
exit
```

This profile uses a **deny-list approach** rather than an allow-list. It allows all syscalls by default (SCMP_ACT_ALLOW) but explicitly blocks dangerous ones that could be used to escape containers, load kernel modules, mount filesystems, or modify system time.

This is more practical than an allow-list because:
- The container runtime can complete initialization
- Common applications work without modification  
- Dangerous operations are still blocked

Deploy a pod using this custom profile:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-restricted
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: restricted.json
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/seccomp-restricted
```

Check that normal operations work:

```bash
kubectl exec seccomp-restricted -- echo "test"
kubectl exec seccomp-restricted -- ls /
kubectl exec seccomp-restricted -- ps aux
```

All these commands should succeed. Now try operations blocked by the profile. Try mounting a filesystem:

```bash
kubectl exec seccomp-restricted -- mount -t tmpfs tmpfs /mnt
```

You should see:

```
mount: /mnt: permission denied.
```

Try modifying the system time:

```bash
kubectl exec seccomp-restricted -- date -s "2025-01-01 00:00:00"
```

You should see:

```
date: can't set date: Operation not permitted
```

Try loading a kernel module (which would require the kernel module file, but the syscall is blocked):

```bash
kubectl exec seccomp-restricted -- unshare -r /bin/sh
```

The profile successfully blocks dangerous operations while allowing the container to function normally for its intended purpose.

### The Challenge of Allow-List Profiles

Creating a minimal allow-list profile (defaultAction: SCMP_ACT_ERRNO with only specific syscalls allowed) is extremely difficult because:

1. The container runtime needs many syscalls just to set up the container environment
2. Different Linux distributions and container runtimes may need different syscalls
3. Applications often use more syscalls than you expect (libc functions can map to surprising syscalls)
4. Debugging blocked syscalls requires kernel audit logs, which most development clusters don't have enabled

If you attempted a truly minimal allow-list profile, the container would likely fail to start with errors like:

```
Error: failed to create containerd task: OCI runtime create failed: 
unable to start container process: operation not permitted
```

This happens because even before your application runs, the container runtime needs to:
- Set up namespaces (clone, unshare)
- Configure cgroups (open, write, close)
- Set up the root filesystem (pivot_root, mount)
- Configure network (socket, bind, connect)
- Execute your application (execve)

For production use, start with RuntimeDefault, which provides a well-tested balance. Only create custom profiles if you have specific compliance requirements and the resources to test them thoroughly.

### Debugging Seccomp Issues

When a seccomp profile blocks a needed syscall, the error messages can be cryptic. The kernel logs contain more detail. To see which syscalls are being blocked, you need to check auditd logs or kernel messages.

With the restricted profile you created, you can test which operations are blocked:

```bash
kubectl exec seccomp-restricted -- mount -t tmpfs tmpfs /mnt 2>&1
kubectl exec seccomp-restricted -- unshare -r /bin/sh 2>&1
```

These operations fail with "Operation not permitted" because the syscalls are explicitly blocked in the profile.

To diagnose why a custom profile is failing, you would typically:

1. Check kernel audit logs on the node (requires auditd to be enabled)
2. Use tools like `strace` outside the container to identify required syscalls
3. Add those syscalls to your profile incrementally
4. Test again until the application works

For production use, RuntimeDefault provides a well-tested balance between security and compatibility. Only create custom deny-list profiles when you need to block specific operations beyond what RuntimeDefault provides. Avoid allow-list profiles unless you have dedicated resources to maintain them.

## AppArmor Profiles

AppArmor (Application Armor) is a Linux Security Module that provides mandatory access control (MAC). Unlike seccomp which filters syscalls, AppArmor defines policies about which files, directories, and capabilities a program can access.

AppArmor policies are path-based. You write rules like "this process can read /etc/nginx/* but cannot write to /var/log/*". The kernel enforces these rules regardless of file ownership or permissions.

### Checking AppArmor Availability

AppArmor must be enabled in the Linux kernel. Check if your nodes have AppArmor:

```bash
docker exec security-demos-worker bash -c "cat /sys/module/apparmor/parameters/enabled"
```

You should see:

```
Y
```

If you see `N` or the file does not exist, AppArmor is not available. In that case, you can still read this section to understand the concepts, but you will not be able to test the examples.

### The Default: No AppArmor Profile

Without an AppArmor profile, containers have no mandatory access control. Their file access is controlled only by traditional Unix permissions.

Deploy a pod without an AppArmor profile:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-apparmor
spec:
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/no-apparmor
```

Check the AppArmor profile:

```bash
kubectl exec no-apparmor -- cat /proc/1/attr/current
```

You might see:

```
docker-default (enforce)
```

Or in some environments:

```
unconfined
```

The `docker-default` profile is Docker's basic AppArmor policy. It provides minimal restrictions but is better than nothing. The `unconfined` status means no AppArmor protection is active.

### Using Container Runtime Default Profile

Kubernetes can instruct the container runtime to apply its default AppArmor profile. For Docker and containerd, this is usually the `docker-default` or `cri-containerd.apparmor.d` profile.

Deploy a pod with the runtime default AppArmor profile:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-runtime-default
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
spec:
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/apparmor-runtime-default
```

Verify the profile is applied:

```bash
kubectl exec apparmor-runtime-default -- cat /proc/1/attr/current
```

You should see:

```
docker-default (enforce)
```

The runtime default profile blocks some dangerous operations like mounting filesystems, accessing raw disk devices, and certain kernel parameters.

Try mounting a filesystem:

```bash
kubectl exec apparmor-runtime-default -- mount -t tmpfs tmpfs /mnt
```

You should see:

```
mount: /mnt: permission denied.
```

Even if the process had the necessary capabilities, AppArmor blocks the mount operation.

### Creating a Custom AppArmor Profile

For tighter control, you can create custom AppArmor profiles. These are text files that define allowed operations using AppArmor's policy language.

Get a shell on the worker node:

```bash
docker exec -it security-demos-worker bash
```

Create a restrictive AppArmor profile:

```bash
cat > /etc/apparmor.d/k8s-restricted <<'EOF'
#include <tunables/global>

profile k8s-restricted flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Allow networking
  network inet tcp,
  network inet udp,
  network inet icmp,

  # Allow basic file operations in standard locations
  /bin/** ix,
  /usr/bin/** ix,
  /lib/** ix,
  /usr/lib/** ix,
  /etc/ld.so.cache r,
  /etc/passwd r,
  /etc/group r,

  # Allow read-only access to common config directories
  /etc/** r,

  # Deny write access to sensitive directories
  deny /etc/** w,
  deny /sys/** w,
  deny /proc/sys/** w,

  # Allow read/write in application-specific directories
  /tmp/** rw,
  /var/tmp/** rw,
  /data/** rw,

  # Deny raw access to devices
  deny /dev/** w,
  deny /proc/kcore r,

  # Deny capability abuse
  deny capability sys_admin,
  deny capability sys_module,
}
EOF
```

Load the profile:

```bash
apparmor_parser -r /etc/apparmor.d/k8s-restricted
```

Verify the profile is loaded:

```bash
apparmor_status | grep k8s-restricted
```

You should see:

```
   k8s-restricted
```

Exit the node:

```bash
exit
```

Deploy a pod using this custom profile:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: apparmor-custom
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/k8s-restricted
spec:
  containers:
  - name: app
    image: alpine
    command: ["sleep", "3600"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/apparmor-custom
```

Verify the profile is active:

```bash
kubectl exec apparmor-custom -- cat /proc/1/attr/current
```

You should see:

```
k8s-restricted (enforce)
```

Test that the profile allows operations in /data:

```bash
kubectl exec apparmor-custom -- sh -c "echo 'test' > /data/file.txt && cat /data/file.txt"
```

You should see:

```
test
```

Now try writing to a restricted location:

```bash
kubectl exec apparmor-custom -- sh -c "echo 'test' > /etc/test.txt"
```

You should see:

```
sh: can't create /etc/test.txt: Permission denied
```

AppArmor blocks the write operation even though traditional file permissions might allow it.

Try reading a sensitive file:

```bash
kubectl exec apparmor-custom -- cat /proc/kcore
```

You should see:

```
cat: /proc/kcore: Permission denied
```

The profile denies access to kernel memory, preventing potential information disclosure.

### AppArmor Best Practices

AppArmor profiles should be developed iteratively. Start with a permissive profile that logs violations without blocking them, then analyze the logs to understand your application's actual needs. Once you have a working profile, switch to enforce mode.

The annotation syntax for AppArmor is still beta in Kubernetes. It uses annotations rather than a native field in the security context. This may change in future API versions.

AppArmor is most common on Debian and Ubuntu systems. Red Hat Enterprise Linux and its derivatives (including Fedora, CentOS, Rocky Linux) use SELinux instead.

## SELinux Contexts

SELinux (Security-Enhanced Linux) is an alternative mandatory access control system used primarily in Red Hat environments. It is more complex than AppArmor but also more powerful and fine-grained.

SELinux uses labels called security contexts. Every process, file, and object has a context with four components: user, role, type, and level. Policies define which types can interact with each other.

### Checking SELinux Status

SELinux is typically disabled or set to permissive mode in development environments like kind clusters. Check the status:

```bash
docker exec security-demos-worker bash -c "getenforce 2>/dev/null || echo 'SELinux not available'"
```

You will likely see:

```
SELinux not available
```

If SELinux is available, you would see `Enforcing`, `Permissive`, or `Disabled`.

### SELinux in Kubernetes

When SELinux is enabled, Kubernetes can set SELinux contexts through the security context. This is done with the `seLinuxOptions` field:

```yaml
spec:
  securityContext:
    seLinuxOptions:
      level: "s0:c123,c456"
      role: "object_r"
      type: "container_t"
      user: "system_u"
```

The most important field is `type`. SELinux policies control what types can access other types. For example, the `container_t` type is designed for container processes and has access to specific file types but not others.

### Why SELinux Matters

In production Red Hat environments, SELinux provides defense in depth. Even if an attacker escapes a container, SELinux policies can prevent access to host resources that the container type should not interact with.

However, SELinux adds operational complexity. Policies must be carefully designed and tested. Misconfigurations can prevent legitimate operations, causing hard-to-diagnose failures.

For most Kubernetes users, especially those on Debian or Ubuntu, AppArmor or seccomp profiles provide sufficient mandatory access control without SELinux's complexity.

### When to Use SELinux

Use SELinux when:

* You are running on Red Hat Enterprise Linux or derivatives
* You have compliance requirements mandating mandatory access control
* You have expertise in SELinux policy development
* You are running multi-tenant workloads that need strong isolation

For other scenarios, focus on seccomp and AppArmor first. They are simpler to configure and cover most security needs.

## Troubleshooting Security Context Issues

Security contexts can cause pods to fail in ways that are not immediately obvious. Understanding common failure modes helps you diagnose and fix issues quickly.

### Issue: Pod Fails with CreateContainerConfigError

This usually happens when runAsNonRoot is true but the image defaults to root.

Create an example:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-nonroot-fail
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: nginx:alpine
EOF
```

Check the pod status:

```bash
kubectl get pod debug-nonroot-fail
```

You should see:

```
NAME                   READY   STATUS                       RESTARTS   AGE
debug-nonroot-fail     0/1     CreateContainerConfigError   0          5s
```

Check the events:

```bash
kubectl describe pod debug-nonroot-fail | tail -5
```

You should see:

```
Error: container has runAsNonRoot and image will run as root
```

Fix this by explicitly setting runAsUser to a non-root UID:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-nonroot-fixed
spec:
  securityContext:
    runAsUser: 101
    runAsNonRoot: true
  containers:
  - name: app
    image: nginx:alpine
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/debug-nonroot-fixed
```

The pod now starts successfully.

### Issue: Container Crashes with Permission Denied

This often happens when the container tries to write to the root filesystem with readOnlyRootFilesystem enabled.

Create an example:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-readonly-crash
spec:
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      readOnlyRootFilesystem: true
EOF
```

Wait a moment and check the status:

```bash
kubectl get pod debug-readonly-crash
```

You should see:

```
NAME                    READY   STATUS             RESTARTS      AGE
debug-readonly-crash    0/1     CrashLoopBackOff   2 (10s ago)   30s
```

Check the logs:

```bash
kubectl logs debug-readonly-crash
```

You should see errors about failing to write to /var/cache/nginx or /var/run.

Fix this by mounting writable volumes:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-readonly-fixed
spec:
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/debug-readonly-fixed
```

The pod starts successfully now that nginx has writable locations.

### Issue: Application Fails with "Operation Not Permitted"

This can be caused by missing capabilities, seccomp blocking a syscall, or AppArmor denying access.

Create an example where an application needs a capability:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-capability-missing
spec:
  securityContext:
    runAsUser: 101
    runAsGroup: 101
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      capabilities:
        drop: ["ALL"]
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF
```

Wait a moment and check:

```bash
kubectl get pod debug-capability-missing
```

You should see CrashLoopBackOff. Check logs:

```bash
kubectl logs debug-capability-missing
```

You should see:

```
nginx: [emerg] bind() to 0.0.0.0:80 failed (13: Permission denied)
```

Add the required capability:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-capability-fixed
spec:
  securityContext:
    runAsUser: 101
    runAsGroup: 101
  containers:
  - name: app
    image: nginx:alpine
    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
    volumeMounts:
    - name: cache
      mountPath: /var/cache/nginx
    - name: run
      mountPath: /var/run
  volumes:
  - name: cache
    emptyDir: {}
  - name: run
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/debug-capability-fixed
```

The pod starts successfully.

### Issue: Volume Permission Problems

When containers cannot access files in volumes, check fsGroup and runAsGroup:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: debug-volume-permission
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 2000
    fsGroup: 3000
  containers:
  - name: writer
    image: alpine
    command: ["sh", "-c"]
    args:
    - |
      id
      ls -ld /data
      echo "test" > /data/test.txt
      ls -l /data/test.txt
      sleep 3600
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/debug-volume-permission
```

Check the output:

```bash
kubectl logs debug-volume-permission
```

You should see:

```
uid=1000 gid=2000 groups=2000,3000
drwxrwsrwx 2 root 3000 40 Oct 29 12:00 /data
-rw-r--r-- 1 1000 3000 5 Oct 29 12:00 /data/test.txt
```

The file inherits group 3000 from fsGroup, allowing all containers in the pod to access it.

### Diagnostic Strategy

When a pod fails due to security contexts:

1. Check pod events with `kubectl describe pod <name>`
2. Check container logs with `kubectl logs <pod> -c <container>`
3. Verify user/group with `kubectl exec <pod> -- id`
4. Check capabilities with `kubectl exec <pod> -- cat /proc/1/status | grep Cap`
5. Check seccomp status with `kubectl exec <pod> -- cat /proc/1/status | grep Seccomp`
6. Check AppArmor profile with `kubectl exec <pod> -- cat /proc/1/attr/current`
7. Verify file permissions with `kubectl exec <pod> -- ls -l <path>`

Start by removing security restrictions one at a time until the pod works, then add them back incrementally while testing. This isolates which restriction causes the issue.

## Combining All Security Mechanisms

Production pods should layer multiple security controls. Here is a comprehensive example:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: production-secure
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: runtime/default
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    runAsNonRoot: true
    fsGroup: 3000
    seccompProfile:
      type: RuntimeDefault
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
    - name: data
      mountPath: /data
  volumes:
  - name: tmp
    emptyDir: {}
  - name: data
    emptyDir: {}
EOF
```

Wait for the pod to be ready:

```bash
kubectl wait --for=condition=ready pod/production-secure
```

Verify all security settings:

```bash
echo "=== User and Groups ==="
kubectl exec production-secure -- id

echo -e "\n=== Capabilities ==="
kubectl exec production-secure -- cat /proc/1/status | grep Cap

echo -e "\n=== Seccomp ==="
kubectl exec production-secure -- cat /proc/1/status | grep Seccomp

echo -e "\n=== AppArmor ==="
kubectl exec production-secure -- cat /proc/1/attr/current

echo -e "\n=== NoNewPrivs ==="
kubectl exec production-secure -- cat /proc/1/status | grep NoNewPrivs

echo -e "\n=== Filesystem ==="
kubectl exec production-secure -- mount | grep "on / "
```

You should see comprehensive security protections across all layers.

## Cleaning Up

Delete all demonstration pods:

```bash
kubectl delete pod volume-permission-problem shared-volume-pod fsgroup-optimized \
  no-seccomp seccomp-runtime-default seccomp-restricted \
  no-apparmor apparmor-runtime-default apparmor-custom \
  debug-nonroot-fail debug-nonroot-fixed debug-readonly-crash \
  debug-readonly-fixed debug-capability-missing debug-capability-fixed \
  debug-volume-permission production-secure \
  --force --grace-period=0
```

Clean up the seccomp and AppArmor profiles on the node (if created):

```bash
docker exec security-demos-worker bash -c "rm -f /var/lib/kubelet/seccomp/restricted.json"
docker exec security-demos-worker bash -c "apparmor_parser -R /etc/apparmor.d/k8s-restricted 2>/dev/null || true"
```

## Summary

You have explored advanced security contexts that build additional defensive layers on top of basic user and capability controls:

* **fsGroup** ensures all containers in a pod can access shared volumes by setting group ownership and adding supplementary groups. Use `fsGroupChangePolicy: OnRootMismatch` to optimize startup time for persistent volumes.

* **Seccomp profiles** filter which system calls containers can invoke. RuntimeDefault blocks dangerous syscalls while allowing normal operations. Custom profiles enable fine-grained control but require careful testing.

* **AppArmor profiles** provide mandatory access control based on file paths and operations. They complement seccomp by controlling what containers can access rather than how they access it.

* **SELinux contexts** offer powerful mandatory access control in Red Hat environments but add operational complexity. Use them when compliance requires or when you have dedicated SELinux expertise.

* **Troubleshooting** security contexts requires systematic diagnosis. Check events, logs, and kernel status files to identify which restriction causes failures. Remove restrictions incrementally to isolate issues, then add them back with proper configuration.

Defense in depth means layering multiple independent controls. If one fails or is bypassed, others still provide protection. Production workloads should combine non-root users, dropped capabilities, seccomp filtering, read-only filesystems, and mandatory access control.

Each layer has a specific purpose. User permissions control who can do what based on identity. Capabilities grant specific privileges without full root access. Seccomp limits which kernel operations are possible. AppArmor and SELinux enforce policies about resource access. Together, they make exploitation progressively harder.

## Next Steps

In the next section, you will explore Pod Security Standards and Pod Security Admission, which provide policy-based enforcement of these security contexts across your cluster. You will also learn about NetworkPolicies and how to restrict pod-to-pod communication.
