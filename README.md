# Kubernetes Security the Hard Way

This tutorial walks you through understanding Kubernetes security from the ground up. You will learn how Linux kernel primitives translate into Kubernetes security controls, why certain configurations matter, and how to apply them effectively.

Kubernetes Security the Hard Way is optimized for learning. Each concept builds on fundamental Linux mechanisms before showing how Kubernetes abstracts them. You will run practical demonstrations using Python containers to see security controls in action.

## Target Audience

This tutorial is for people who want to understand Kubernetes security at a fundamental level. If you have deployed applications to Kubernetes and want to understand what happens beneath declarative YAML configurations, this guide is for you.

## Cluster Details

Kubernetes Security the Hard Way uses [kind](https://kind.sigs.k8s.io/) (Kubernetes in Docker) to provide a local cluster. This approach works consistently across Linux, macOS, and Windows with Docker Desktop.

The cluster configuration includes:

* One control plane node (tainted to prevent workload scheduling)
* One worker node (where all demo pods run)
* Port mappings for ingress traffic
* Standard Kubernetes security features enabled

## What You Will Learn

This tutorial covers Kubernetes security through practical demonstrations:

* **Security Contexts** - How Linux UIDs, capabilities, and filesystem permissions map to Kubernetes pod security
* **Runtime Security** - Understanding container isolation, privilege escalation, and process boundaries  
* **Seccomp and AppArmor** - Syscall filtering and mandatory access control in containerized workloads
* **Image Security** - Building minimal containers, managing secrets, and preventing supply chain attacks

Each module starts with Linux kernel concepts, shows how container runtimes implement them, and demonstrates the Kubernetes abstraction layer.

## Prerequisites

### Required Knowledge

* Basic Kubernetes concepts (pods, deployments, services)
* Command line experience (bash or PowerShell)
* Fundamental Linux concepts (users, processes, file permissions)

### Required Software

* **Docker Desktop** (Windows/macOS) or **Docker Engine** (Linux)
* **kubectl** - Kubernetes command-line tool
* **kind** - Kubernetes in Docker
* **Python 3.9+** - For building demo containers

Installation instructions are in [docs/01-prerequisites.md](docs/01-prerequisites.md).

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/davealtena/kubernetes-security-the-hard-way.git
cd kubernetes-security-the-hard-way
```

### Create the Cluster

```bash
kind create cluster --config kind-config.yaml
```

This creates a cluster named `security-demos`. Verify it is running:

```bash
kubectl cluster-info
kubectl get nodes
```

You should see two nodes: one control plane and one worker.

### Clean Up

When you are done, delete the cluster:

```bash
kind delete cluster --name security-demos
```

## Tutorial Modules

### ✅ [Prerequisites](docs/01-prerequisites.md)

Install and configure the tools required for this tutorial.

### 🚧 Security Contexts - In Progress

Understand how Kubernetes controls container privileges through Linux primitives.

**Available now:**
* [Linux Primitives](docs/02-security-contexts/01-linux-primitives.md) - System calls, cgroups, and namespaces

**Coming soon:**
* User Permissions and Security Contexts - `runAsUser`, `runAsNonRoot`, user namespaces
* Linux Capabilities - Fine-grained privilege control, `allowPrivilegeEscalation`
* Filesystem Security - `readOnlyRootFilesystem`, `fsGroup`, volume permissions

### 📋 Runtime Security - Planned

Learn how container runtimes enforce isolation and what breaks when processes escape boundaries.

### 📋 Seccomp and AppArmor - Planned

Filter system calls and enforce mandatory access control policies on running containers.

### 📋 Image Security - Planned

Build secure container images and prevent supply chain vulnerabilities.

## Philosophy

Security in Kubernetes is layered. No single control provides complete protection. Instead, multiple mechanisms work together to reduce attack surface and limit the impact of compromised workloads.

This tutorial emphasizes understanding over memorization. When you understand why a security control exists and what Linux primitive it leverages, you can apply it correctly without relying on copy-pasted configurations.

Each demonstration in this tutorial shows both secure and insecure configurations. You will see what breaks, why it breaks, and how to fix it. This approach builds intuition that survives changes in tooling and best practices.

## Contributing

This is an open educational resource. If you find errors, have suggestions, or want to add demonstrations, open an issue or submit a pull request.

## License

This work is licensed under the MIT License. See [LICENSE](LICENSE) for details.
