# Project TeleGraph: Cloud IAM Directed Attack Graph & Telemetry Fusion Engine

An automated framework for modeling Cloud Identity and Access Management (IAM) permissions as Directed Attack Graphs, detecting real-time privilege escalation traversals via CloudTrail telemetry, and synthesizing minimal least-privilege policies.

---

## 1. Abstract & Research Motivation

In modern multi-tenant cloud environments (e.g., AWS, GCP), Identity and Access Management (IAM) constitutes the primary security perimeter. However, access control policy evaluation is non-trivial: permissions interact transitively across identities, roles, and resources. Standard compliance scanners rely on local pattern matching (e.g., checking for `"Action": "*"`), leaving organizations vulnerable to **multi-hop privilege escalation attacks** where an unprivileged identity chains intermediate capabilities to reach root privileges.

Furthermore, static policy analysis cannot evaluate whether granted permissions are actually required for business operations. **Project TeleGraph** addresses these limitations by:
1. Formally modeling declarative cloud infrastructure (Terraform) as a **Directed Attack Graph** $\mathcal{G} = (\mathcal{V}, \mathcal{E})$.
2. Executing an optimal **Breadth-First Search (BFS)** reachability algorithm ($\mathcal{O}(|\mathcal{V}| + |\mathcal{E}|)$) with predecessor backtracking to extract full attack trajectories.
3. Fusing static graph topology with dynamic audit event streams (AWS CloudTrail) to detect active path traversal on-demand.
4. Implementing a threshold-based ($\tau = 0.7$) **Access Mining Engine** that quantifies privilege waste and automatically synthesizes least-privilege IAM policies.

---

## 2. Threat Model & System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        INFRASTRUCTURE SUBSTRATE                        │
│             Terraform (config.tf) -> LocalStack / Moto API             │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         ▼                                                   ▼
┌──────────────────────────────────┐        ┌──────────────────────────────────┐
│      STATIC SECURITY PLANE       │        │      DYNAMIC TELEMETRY PLANE     │
│   IAM Policies & Trust Chains    │        │      AWS CloudTrail Streams      │
└────────────────┬─────────────────┘        └────────────────┬─────────────────┘
                 │                                           │
                 ▼                                           ▼
┌──────────────────────────────────┐        ┌──────────────────────────────────┐
│   DIRECTED ATTACK GRAPH (DAG)    │        │      OBSERVED ACTION MINER       │
│  G = (V, E) with Synthetic Root  │        │   A_used = {Unique API Calls}    │
└────────────────┬─────────────────┘        └────────────────┬─────────────────┘
                 │                                           │
                 └────────────────────┬──────────────────────┘
                                      ▼
             ┌─────────────────────────────────────────────────┐
             │       GRAPH-TELEMETRY FUSION ENGINE             │
             │  1. Active Escalation Detection (len(path) > 2) │
             │  2. Threshold Utilization Ratio (tau < 0.7)     │
             └────────────────────────┬────────────────────────┘
                                      │
                                      ▼
             ┌─────────────────────────────────────────────────┐
             │       AUTOMATED REMEDIATION SYNTHESIZER         │
             │    Synthesizes tailored least-privilege JSON    │
             └─────────────────────────────────────────────────┘
```

### The Transitive Escalation Vector (The Charlie Scenario)
* **Identity `admin`**: Holds direct root administrative permissions (`"Action": "*"`).
* **Identity `charlie`**: Holds zero direct admin rights; granted solely `iam:CreateAccessKey` targeting `admin`.
* **Vulnerability**: Charlie generates programmatic access keys for `admin`, usurping root control.
* **Attack Chain**:
  ```mermaid
  flowchart LR
      charlie["charlie"] -->|iam:CreateAccessKey| admin["admin"]
      admin -->|Action: *| ROOT_ADMIN["ROOT_ADMIN"]
  ```

---

## 3. Mathematical & Algorithmic Formulation

### 3.1 Graph Representation
* **Vertices ($\mathcal{V}$)**: Identities (users, roles) augmented by a synthetic sink node `ROOT_ADMIN`.
* **Directed Edges ($\mathcal{E}$)**: A directed edge $(u, v) \in \mathcal{E}$ exists if identity $u$ possesses an action classified under the **Escalation Rules Taxonomy** targeting identity $v$.

### 3.2 Graph Traversal Complexity
Reachability from an unprivileged identity to `ROOT_ADMIN` is computed using Breadth-First Search (BFS):
* **Time Complexity**: $\mathcal{O}(|\mathcal{V}| + |\mathcal{E}|)$
  * In-memory double-ended queue (`collections.deque`) ensures $\mathcal{O}(1)$ node de-queuing without array shifting overhead.
  * Hash set lookup ensures $\mathcal{O}(1)$ cycle and visited detection.
* **Space Complexity**: $\mathcal{O}(|\mathcal{V}|)$
  * Retains a predecessor mapping dictionary $\mathcal{P}: \mathcal{V} \to \mathcal{V}$ enabling backwards path reconstruction.

### 3.3 Privilege Utilization Ratio & Threshold
Let $A_{\text{granted}}$ denote the set of actions authorized by attached policies for identity $u$. Let $A_{\text{observed}}$ denote the set of unique actions recorded in telemetry.

The **Privilege Utilization Ratio** $R(u)$ is defined as:
$$R(u) = \frac{|A_{\text{observed}} \cap A_{\text{granted}}|}{|A_{\text{granted}}|}$$

* **Wildcard Root Bloat**: If `"*" \in A_{\text{granted}}`, then $|A_{\text{granted}}| \approx 14,000$, yielding $R(u) \approx 0.0$.
* **Tolerance Threshold ($\tau = 0.70$)**: If $R(u) < \tau$, the identity is marked for automated remediation.

---

## 4. Repository Structure

```text
.
├── terraform/
│   └── config.tf                 # Declarative Terraform IaC vulnerable testbed
├── examples/                     # Sample synthesized least-privilege policies
│   ├── recommended_policy_bob.json
│   ├── recommended_policy_chief_admin.json
│   └── recommended_policy_devops_worker_02.json
├── generate_enterprise_lab.py     # Enterprise benchmark generator (102 users, 2,800+ events)
├── generate_telemetry.py         # Baseline CloudTrail event generator
├── simulated_cloudtrail.json     # Simulated audit event stream
├── my_graph_auditor.py           # Directed attack graph builder and BFS reachability engine
├── telemetry_fusion.py           # Event-driven fusion, threat detector, and policy synthesizer
├── .gitignore                    # Build artifacts and credential isolation
└── README.md                     # Research documentation
```

---

## 5. Enterprise-Scale Evaluation & Benchmarking

To evaluate scalability beyond micro-benchmarks, an enterprise topology generator (`generate_enterprise_lab.py`) was implemented:
* **Entities**: 102 active IAM principals across 5 functional departments (`devops`, `backend`, `frontend`, `data`, `finance`).
* **Telemetry**: 2,802 asynchronous CloudTrail audit events.
* **Injected Adversarial Vectors**:
  * `intern_infiltrator` executing privilege escalation targeting `lead_engineer` (→ `ROOT_ADMIN`).
  * `rogue_contractor` executing privilege escalation targeting `chief_admin` (→ `ROOT_ADMIN`).
* **Execution Results**:
  * **Zero False Negatives**: Both multi-hop attack vectors intercepted in real time with exact shortest-path extraction:
    ```text
    [PRIVILEGE ESCALATION] 'intern_infiltrator' actively executed 'iam:CreateAccessKey'! 
       Attack Path: intern_infiltrator -> lead_engineer -> ROOT_ADMIN
    [PRIVILEGE ESCALATION] 'rogue_contractor' actively executed 'iam:CreateAccessKey'! 
       Attack Path: rogue_contractor -> chief_admin -> ROOT_ADMIN
    ```
  * **Automated Least-Privilege Remediation**: Identified dormant root accounts and synthesized tailored JSON policies for all entities with utilization ratio $\rho < 0.70$.

---

## 6. Execution & Verification Guide

### Prerequisites
* Linux (Fedora / Debian / Ubuntu)
* Podman or Docker
* Terraform >= 1.10
* Python >= 3.12 with `boto3`

### Step 1: Initialize Local AWS Mock & Deploy Infrastructure
```bash
# 1. Start the local AWS engine (port 5000)
podman run -d --name local-aws --restart unless-stopped -p 5000:5000 docker.io/motoserver/moto:latest

# 2. Deploy vulnerable IAM topology via Terraform
cd terraform
terraform init
terraform apply -auto-approve
cd ..
```

### Step 2: Run Enterprise Benchmark
```bash
# Provision 102 enterprise users and generate 2,800+ telemetry events
python generate_enterprise_lab.py

# Ingest telemetry, compute graph reachability, and synthesize remediations
python telemetry_fusion.py
```

---

## 6. SnT / Academic Research Alignment
* **Research Group Alignment**: Systems and Network Security (Prof. Radu State / SEDAN group) & CritiX (Prof. Marcus Völp).
* **Core Competencies Demonstrated**: Declarative Infrastructure as Code (Terraform), Directed Graph Reachability, Asymptotic Complexity Optimization, Cloud-Native Telemetry Mining, Automated Policy Synthesis.
