# Prerequisites

This page covers the tools you need to run Kubernetes Security the Hard Way. Installation steps are provided for Linux, macOS, and Windows.

## Docker

Kubernetes in Docker (kind) requires a container runtime. Docker Desktop provides the most consistent experience across all platforms.

### Linux

Install Docker Engine using the official repositories:

```bash
# Update package index
sudo apt-get update

# Install prerequisites
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up the repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker
```

Verify the installation:

```bash
docker --version
docker run hello-world
```

### macOS

Download and install Docker Desktop from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop).

After installation, start Docker Desktop from Applications. Wait for the Docker icon to show "running" in the menu bar.

Verify the installation:

```bash
docker --version
docker run hello-world
```

### Windows

Download and install Docker Desktop from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop).

Docker Desktop on Windows requires WSL 2. The installer will enable this if needed. After installation, start Docker Desktop from the Start menu.

Verify the installation in PowerShell:

```powershell
docker --version
docker run hello-world
```

## kubectl

kubectl is the Kubernetes command-line tool. You will use it to interact with your cluster.

### Linux

```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

Verify the installation:

```bash
kubectl version --client
```

### macOS

Using Homebrew:

```bash
brew install kubectl
```

Or download directly:

```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/arm64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

Verify the installation:

```bash
kubectl version --client
```

### Windows

Using Chocolatey:

```powershell
choco install kubernetes-cli
```

Or download the binary directly from [kubernetes.io/docs/tasks/tools/install-kubectl-windows](https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/).

Add kubectl to your PATH, then verify in PowerShell:

```powershell
kubectl version --client
```

## kind

kind runs Kubernetes clusters using Docker containers as nodes. It works identically on all platforms.

### Linux

```bash
# For AMD64 / x86_64
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# For ARM64
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-arm64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

Verify the installation:

```bash
kind version
```

### macOS

Using Homebrew:

```bash
brew install kind
```

Or download directly:

```bash
# For Apple Silicon
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-darwin-arm64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# For Intel
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-darwin-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

Verify the installation:

```bash
kind version
```

### Windows

Using Chocolatey:

```powershell
choco install kind
```

Or download the binary from [kind.sigs.k8s.io](https://kind.sigs.k8s.io/docs/user/quick-start#installation), add it to your PATH, and verify in PowerShell:

```powershell
kind version
```

## Python

Python 3.9 or later is required to build the demonstration containers.

### Linux

Most distributions include Python 3. Verify:

```bash
python3 --version
```

If not installed:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip
```

### macOS

macOS includes Python 3, but you may want a newer version via Homebrew:

```bash
brew install python3
```

Verify:

```bash
python3 --version
```

### Windows

Download and install Python from [python.org/downloads](https://www.python.org/downloads/). During installation, enable "Add Python to PATH".

Verify in PowerShell:

```powershell
python --version
```

## Verification

After installing all prerequisites, verify that everything works:

### Create a Test Cluster

```bash
kind create cluster --name test
```

### Check Cluster Access

```bash
kubectl cluster-info --context kind-test
kubectl get nodes
```

You should see one node in Ready status.

### Delete the Test Cluster

```bash
kind delete cluster --name test
```

## Next Steps

With all tools installed, proceed to [Security Contexts](../02-security-contexts/) to begin the tutorial.
