# CS-BPG / NetSentinel — Security Detection Method

This document describes the main idea behind a security-detection method called **CS-BPG**, and the **NetSentinel** system built around it, which uses Graph Neural Networks (GNNs) to detect malicious abuse of legitimate services.

---

## 1. The Basic Idea

An attacker can make one network connection look completely normal, but it's much harder to make the **entire sequence** of their activities look normal.

For example, malware might use legitimate services like GitHub, Telegram, Google Drive, etc. None of those services is suspicious by itself.

But if the same computer contacts several of them in a particular order, that combination can be a strong warning sign.

Think of it like this:

- Going to a pharmacy → normal.
- Going to a bank → normal.
- Going to a hardware store → normal.

> But if someone visits those places in a very specific sequence as part of a suspicious pattern, the overall behavior may tell you much more than any individual visit.

### What does "network signature of a single legitimate service" mean?

A network signature is basically the **observable characteristics of network traffic**.

An attacker might make malware communicating with Telegram look like ordinary Telegram traffic. So the security system might think:

> "Telegram traffic? That's normal."

But the attacker still needs to perform other activities to actually accomplish their goal. That's where the **sequence** becomes useful.

### The example

The infected computer in this example is an **information stealer** — malware designed to collect information from a victim. Its activity might look like this:

**1. Reconnaissance → ip-api.com / ipify.org**

First, the malware asks an IP/geolocation service: *"Where is this computer located?"* It may use that information to determine whether it is running on a real victim's computer or inside an analysis environment.

```
Computer → IP/geolocation service
```

**2. Payload delivery → Pastebin / GitHub**

Next, it contacts a legitimate service such as GitHub or Pastebin and retrieves additional information, code, or configuration.

```
Computer → GitHub/Pastebin → retrieves something
```

Importantly, GitHub and Pastebin themselves aren't necessarily malicious. They're legitimate services that can be abused by malware.

**3. Command & Control → Telegram**

Then the malware repeatedly contacts Telegram. This is essentially: *"Do I have any instructions from the attacker?"* It keeps polling periodically, waiting for commands.

```
Computer ↔ Telegram ↔ attacker instructions
```

**4. Exfiltration → Google Drive**

Finally, after receiving instructions, the malware sends stolen information somewhere controlled by the attacker, in this example through Google Drive.

```
Computer → Google Drive → stolen information
```

### Why is the sequence important?

Look at the whole chain:

```
Geolocation → GitHub/Pastebin → Telegram → Google Drive
```

Each individual interaction could potentially be legitimate. But seeing the same machine interact with these different services in a particular **sequence and behavioral pattern** can be much more suspicious.

That's the core hypothesis:

> Don't just ask "Is this connection suspicious?" Ask "What sequence of things is this computer doing?"

This is similar to recognizing a person not from **one action**, but from their **entire pattern of actions**.

**In one sentence:** CS-BPG is based on the idea that individual network connections can be disguised as legitimate, but the combination, order, and timing of multiple legitimate-service interactions can reveal that a computer is actually going through a malicious intrusion lifecycle.

---

## 2. What "LSA Traffic" Means

In this context, **"LSA traffic"** appears to mean a type of **low-and-slow network attack/traffic pattern designed to evade traditional detection systems**.

- **Low-and-slow:** It sends traffic gradually rather than flooding a network, so it doesn't look like a typical DDoS attack.
- **Uses port 443:** It communicates over HTTPS (port 443), which is normal and extremely common.
- **Uses trusted domains:** Instead of connecting to obviously suspicious domains, it may communicate through reputable/root domains.
- **Individual packets look normal:** Each packet by itself doesn't necessarily contain anything suspicious.
- **Why older detection models struggle:** Traditional security models often look for obvious indicators — high traffic volume, port scanning, suspicious domains, unusual packets, etc. LSA traffic deliberately avoids those indicators, resulting in **false negatives** (the system says "safe" when the traffic is actually malicious).

So, in plain English:

> LSA traffic is designed to hide malicious activity inside traffic that looks normal, making it difficult for conventional security tools to detect.

---

## 3. Behavioral Context, Not Single Connections

For example:

> "This computer made 500 API calls to Microsoft → suspicious."

But a smarter system would ask:

> "Who is making these calls? Is this a known developer machine? Is this part of a scheduled CI/CD job? Has this behavior happened every day for months? What data is being accessed?"

---

## 4. GNNs for Intrusion Detection: GraphSAGE → E-GraphSAGE

In network intrusion detection, the environment is naturally modeled as a graph where the computing devices (hosts, servers) represent the **nodes**, and the communication flows (TCP/UDP sessions) represent the **edges**. Early applications of GNNs in this domain relied on foundational architectures like Graph Convolutional Networks (GCNs) and GraphSAGE.

GraphSAGE (Graph Sample and Aggregate) was a critical breakthrough because it introduced an **inductive learning paradigm**. Instead of requiring the entire graph structure to be present during training (which is impossible for a continuously evolving enterprise network), GraphSAGE learns a generalized function to generate embeddings by sampling and aggregating features from a node's local, multi-hop neighborhood. This allows the model to instantly generate embeddings for new hosts or new service interactions as they appear on the network.

However, traditional GraphSAGE and GCN architectures are **node-centric**; they aggregate node features but largely ignore edge attributes. In network security, discarding edge features is a fatal flaw because the most discriminative information — such as flow duration, byte counts, and packet timing statistics — is carried by the network flows (the edges), not the hosts (the nodes).

To resolve this limitation, researchers developed edge-centric architectures, with **E-GraphSAGE** being the most prominent. E-GraphSAGE explicitly modifies the aggregation function to ingest both node attributes and edge features during the message-passing phase. This dual-focus approach ensures that the model understands not just *who* a host is communicating with, but the exact nature and volume of that communication, enabling the detection of complex attack patterns that traditional models overlook.

> **So GraphSAGE was made for this purpose — but what's the catch? Why did it fail?**

GraphSAGE can absolutely be used for network intrusion detection, but the "catch" is that standard GraphSAGE was **not designed to treat the network communication itself as the main source of information**.

### 1. What standard GraphSAGE does

Suppose your network looks like:

```
Laptop A → GitHub → Telegram → Google Drive
```

You can represent it as a graph:

- **Nodes:** Laptop A, GitHub, Telegram, Google Drive
- **Edges:** the communication between them

GraphSAGE looks at a node and asks: *"What are the characteristics of this node, and what do its neighboring nodes look like?"* It then aggregates information from those neighbors.

```
Laptop A
   ↓
looks at GitHub, Telegram, etc.
   ↓
combines their information
   ↓
creates an embedding representing Laptop A
```

That's useful because GraphSAGE can also handle new nodes that weren't present during training.

### 2. So what's the problem?

The important information in network security often isn't *who* is talking to whom. It's *how* they're talking. For example:

```
Laptop A ───────────→ Telegram
          500 bytes
          every 30 seconds
          for 6 hours
```

The edge — the communication — contains information such as:

- number of packets
- bytes sent/received
- connection duration
- packet timing
- TCP/UDP characteristics
- direction of traffic
- frequency of connections

Those details can be extremely important for detecting malware. But a basic GraphSAGE setup may primarily aggregate node information. So it can understand:

> "Laptop A is connected to Telegram."

But it may not adequately understand:

> "Laptop A contacts Telegram every 30 seconds, sends tiny requests, waits, receives a response, and repeats this for six hours."

That second piece is often where the malicious behavior is hiding.

### 3. An analogy

Imagine investigating phone calls. Traditional GraphSAGE:

- Alice called Bob.
- Bob called Charlie.
- Charlie called David.

You learn the relationship structure. But you don't necessarily know:

> Alice called Bob 400 times, every 30 seconds, for 8 hours, with each call lasting 2 seconds.

That information is associated with the connection between the people. In network security, that connection is the **edge**.

### 4. Why does E-GraphSAGE help?

E-GraphSAGE essentially says: *Don't just look at the nodes. Look at the nodes AND the edges.* So instead of:

```
Host → Host
```

it can reason about:

```
Host → [duration, bytes, packets, timing, protocol] → Host
```

That gives the model substantially more information about what the communication actually looks like.

### 5. But there's an even bigger catch

GraphSAGE didn't necessarily "fail" because the algorithm itself was bad. Rather, the **representation of the problem** can throw away information before GraphSAGE even gets a chance to learn it.

If you construct your graph like:

```
Host A ───── Host B
```

and don't meaningfully encode the communication properties on that edge, you've effectively told the model *"These two machines communicated,"* but you've hidden **how, when, how often, how much, and in what pattern** they communicated. And for modern network attacks, those behavioral details can be the most valuable signals.

The progression is therefore roughly:

```
GCN / basic GraphSAGE
→ Great at learning node + neighborhood structure
→ But edge/flow information may be underrepresented
→ Important network-traffic behavior gets lost
→ E-GraphSAGE
→ Explicitly incorporates edge/flow attributes
→ Better representation of communication behavior
```

This connects directly to the earlier idea: if an attacker makes each individual connection look legitimate, the security model needs to learn the **behavioral pattern across those connections** — not just recognize the individual services involved.

---

## 5. Self-Supervised Learning & Masked Autoencoders (GraphIDS)

A significant operational hurdle in deploying deep learning for intrusion detection is the reliance on massive, accurately labeled datasets. In the context of LSA, where the permutations of legitimate cloud services are virtually infinite, supervised learning is impractical.

The solution lies in **self-supervised representation learning**, specifically using graph-based masked autoencoders. In frameworks like **GraphIDS**, a GNN encoder (such as E-GraphSAGE) processes the temporal graph to learn the local topological context and edge features of benign, everyday network traffic. A Transformer-based decoder then attempts to reconstruct the original graph structure from these learned embeddings.

During active inference, the system operates on the principle of **reconstruction error**. Legitimate developer workflows, cloud synchronization, and user browsing generate communication patterns that the model has seen and learned to reconstruct accurately, yielding a low error rate. Conversely, an LSA kill chain forces the host to execute a sequence of interactions that deviates significantly from its established structural baseline. The model fails to reconstruct this anomalous subgraph accurately, resulting in a severe spike in reconstruction error, instantly flagging the activity as a potential intrusion. This approach entirely removes the dependency on malicious labels during training, allowing the system to detect novel, zero-day abuse of legitimate services.

The easiest way to understand it is:

> Teach the model what "normal" looks like, then detect things that are difficult for it to reconstruct as normal.

### 1. Why is labeled data a problem?

Traditional supervised ML needs examples like:

```
Traffic A → BENIGN
Traffic B → BENIGN
Traffic C → MALWARE
Traffic D → MALWARE
```

You need lots of accurately labeled examples. But with LSA, there could be an enormous number of combinations of legitimate services:

```
GitHub + Slack
GitHub + Google Drive
Microsoft + Slack + GitHub
Dropbox + Teams
...
```

And attackers can create new combinations you've never seen before. So you can't realistically collect and label every possible malicious variation.

### 2. Instead, learn what normal looks like

The proposed approach is **self-supervised learning**. You give the model lots of ordinary enterprise traffic: developers coding, people browsing websites, cloud synchronization, CI/CD systems communicating, etc. The model learns:

> "This is what normal network behavior usually looks like."

Importantly, you don't have to manually label every connection as benign.

### 3. Where does the graph come in?

The network is represented as a graph:

```
       GitHub
         |
         |
Laptop ──┼── Slack
         |
         |
      Google
```

- **Nodes** = computers/services
- **Edges** = communications
- **Edge features** = things like bytes, duration, packet timing, frequency, etc.

The GNN, such as E-GraphSAGE, learns the relationships and communication characteristics.

### 4. What does the autoencoder do?

The system essentially does:

```
Normal network graph → encode → compressed representation → reconstruct graph
```

For normal traffic:

```
Original normal graph
        ↓
      GNN
        ↓
   Representation
        ↓
   Transformer
        ↓
Reconstructed graph
        ↓
     Very similar
```

So the reconstruction error is low. The model is basically saying:

> "Yep, I've seen behavior like this before. I understand it."

### 5. What happens with an attack?

Now suppose malware creates an unusual sequence:

```
Victim
  ↓
IP/geolocation service
  ↓
GitHub
  ↓
Telegram
  ↓
Google Drive
```

Even though each individual service is legitimate, the overall combination and sequence might be unusual for that particular host. The model tries to reconstruct it:

```
Suspicious graph
       ↓
      GNN
       ↓
  Representation
       ↓
   Transformer
       ↓
Reconstructed graph
       ↓
Doesn't match very well ❌
```

Therefore:

```
High reconstruction error → potentially anomalous behavior → alert
```

### 6. What does "masked autoencoder" mean?

Imagine hiding part of the network graph from the model:

```
Laptop → GitHub → [MASKED] → Google Drive
```

The model has to use the information it can see to figure out what belongs in the missing part. By repeatedly doing this during training, it learns the relationships and patterns that normally exist in the network.

It's somewhat like giving someone:

> "Alice went to the office, then ___, then went home."

and asking them to infer the missing part based on what normally happens.

### 7. Why is this useful for zero-day attacks?

Suppose you've never seen a particular piece of malware before. A supervised system might struggle:

> "I've never been trained on this malware → I don't recognize it."

The reconstruction-based system takes a different approach:

> "I've never seen this exact attack, but this behavior doesn't resemble the normal patterns I've learned."

So it can potentially detect previously unseen attacks. That's what **zero-day detection** means here.

### The entire idea in one picture

```
             TRAINING
                 ↓
       Lots of normal traffic
                 ↓
          Build network graph
                 ↓
        E-GraphSAGE + Decoder
                 ↓
       Learn normal behavior
                 ↓
        "Normal baseline"
                 │
                 ▼
             INFERENCE
                 ↓
        New network activity
                 ↓
       Compare/reconstruct it
                 ↓
       ┌─────────┴─────────┐
       ↓                   ↓
  Low error            High error
       ↓                   ↓
   Probably              Possible
    normal               attack 🚨
```

### One important nuance

The approach "entirely removes the dependency on malicious labels." That's broadly the idea, but be careful with the word "entirely."

- You still need to make sure the training data is mostly representative of benign behavior. If malicious activity is present in the training data and the model learns it as "normal," detection can suffer.
- Also, high reconstruction error doesn't automatically mean "attack." It means "this behavior is unusual relative to the learned baseline." Legitimate but novel behavior can also produce a high error.

So the core concept is:

> Don't teach the model every possible attack. Teach it normal network behavior so well that unusual multi-step behavior stands out automatically.

---

## 6. NetSentinel Architecture

### 1. Service Category Resolver

Crucially, the system cannot utilize raw domain names (e.g., `s3-us-west-2.amazonaws.com`) as node identifiers in the graph. Doing so would result in an infinitely expanding, sparse matrix that the neural network could not generalize. Instead, NetSentinel must implement a deterministic *Service Category Resolver*. By referencing threat intelligence taxonomies (such as the LOTS Project and Recorded Future LIS reports), the resolver maps observed domains and IPs to high-level semantic categories.

For example:

| Observed domains                              | Node Type         |
| --------------------------------------------- | ----------------- |
| `drive.google.com`, `api.dropbox.com`         | `Cloud_Storage`   |
| `api.telegram.org`, `discord.com/api`         | `Messaging_API`   |
| `pastebin.com`, `raw.githubusercontent.com`   | `Code_Repo_Paste` |
| `ipify.org`, `ip-api.com`                      | `Recon_API`       |

This abstraction ensures that the GNN learns the *behavioral concept* of the kill chain rather than memorizing brittle, specific infrastructure endpoints.

### 2. Temporal Windowing and Feature Engineering

The continuous network stream is discretized into fixed temporal windows (e.g., `t = 5, 10, 15` minutes). For each window, a directed graph is constructed where edges represent the aggregate communication between an internal host and an external service category.

The edge attributes are meticulously engineered to highlight LSA characteristics:

- **Egress Asymmetry:** The mathematical ratio of bytes uploaded versus bytes downloaded. A high egress asymmetry toward a `Cloud_Storage` node is a primary indicator of data exfiltration (T1567).
- **Polling Coefficient of Variation (CoV):** The statistical variance in the inter-arrival times of the flows. A low CoV toward a `Messaging_API` node strongly indicates automated beaconing, distinguishing it from sporadic human chat behavior.
- **Micro-Timing / FFT Signatures:** A critical, under-explored vector for distinguishing between legitimate human app usage and automated script execution is sub-second latency distribution. When a human clicks a button in a desktop application, there is inherent biological and UI-rendering latency. An automated Python script utilizing the requests library executes with machine-level precision. By applying Fast Fourier Transforms (FFT) to the sequence of packet arrival times, NetSentinel can extract micro-timing frequency signatures as edge features, providing the GNN with deterministic evidence of automation.

### 3. Emulation and Data Strategy

The data generation process must be bisected into benign capture and malicious emulation.

**Benign Context Generation:** The system requires high-fidelity baseline data. This cannot be synthetically generated via random walks; it must be captured from actual, consented enterprise environments. The collection must include:

- Standard browser-based interactions with Google Workspace and Office 365.
- Background synchronization traffic from native agents (OneDrive sync, Dropbox desktop).
- Active use of instant messaging applications (Telegram desktop, Slack, Discord).
- Legitimate developer workflows, including `git pull` operations, CI/CD pipeline triggers, and automated API testing scripts (to properly represent the false-positive generating noise mentioned previously).

**Malicious LSA Emulation:** The generation of the malicious kill chains is the core experimental effort. Researchers must utilize advanced, open-source C2 frameworks capable of routing traffic through third-party services. The *Mythic* C2 framework is uniquely suited for this task. Mythic operates via specialized C2 profiles running in isolated Docker containers, acting as forwarding mechanisms.

Researchers will deploy Mythic agents configured with custom C2 profiles to emulate specific APT behaviors:

- **Emulating Tabbywalk/SideCopy:** Agents configured to poll a dedicated Telegram bot for instructions, execute reconnaissance modules, and subsequently upload collected archives to a Google Drive webhook.
- **Emulating 3CX/HAMMERTOSS:** Agents programmed to fetch initial stagers from a controlled GitHub repository before transitioning to Discord-based C2.

By meticulously labeling this traffic at the *chain* level — rather than the individual flow level — NetSentinel will forge the world's first multi-LIS provenance dataset, providing the necessary mathematical foundation to train and validate the Spatio-Temporal GNN.

### 4. Overcoming Computational Bottlenecks

Deploying a GNN in a live enterprise network introduces severe computational challenges. The graph representing thousands of hosts and millions of flows quickly exceeds GPU VRAM limitations.

NetSentinel must implement advanced sampling and batching techniques:

- **NeighborLoader Mini-Batching:** Utilizing PyG's `NeighborLoader`, the system performs localized sampling as introduced by GraphSAGE. Instead of calculating gradients across the entire network, `NeighborLoader` samples a fixed maximum number of neighbors (e.g., 15 neighbors at hop 1, 10 at hop 2) for a given target node. This limits the computational graph to a fixed size per batch, enabling the model to scale infinitely across massive enterprise networks.
- **Temporal Index-Batching:** To optimize the recurrent processing of temporal snapshots, PyTorch Geometric Temporal supports *GPU-index-batching*. This technique shifts the entire preprocessing workload into GPU memory, utilizing a single CPU-to-GPU memory copy rather than repetitive batch-level transfers during continuous training. This architectural choice virtually eliminates the I/O bottleneck that cripples real-time intrusion detection systems.

---

## 7. Architecture, Threat Model & Open Question

This section records the deployment architecture we converged on, stated honestly against its prior art and its failure modes. It is deliberately *not* claiming the mechanism is novel — the defensible contribution is the application to cross-service LSA detection and the cost/coverage engineering, not the cascade itself.

### The locked architecture: expensive teacher → distilled cheap student

> An **expensive teacher** model (E-GraphSAGE + Transformer reconstruction) runs on **all** traffic during a **tiered enrollment window** whose length is set by the plan the enterprise purchased. Hosts that pass enrollment are demoted to an always-on **distilled cheap student** model. The student re-escalates a host back to the teacher on **(a)** any detected anomaly, **(b)** random sampling (unpredictable, so it cannot be timed or waited out), or **(c)** a behavioural change. **Rolling re-enrollment** re-baselines hosts on a sliding schedule; **threat-intelligence scrapers** keep the Service Category Resolver taxonomy current. The honest cost/coverage tradeoff is exposed as three tunable knobs, and the open research question is how cheap the student can get while staying sensitive enough to trigger re-escalation on real attacks.

```
                    ┌──────────── tiered enrollment budget (plan) ────────────┐
                    ▼                                                          │
ALL traffic ──► TEACHER (expensive, E-GraphSAGE + Transformer)                │
                    │  build per-host behavioural baseline                    │
                    ▼                                                          │
              certify host ──► STUDENT (distilled, cheap, always-on) ─────────┤
                                     │                                         │
                    re-escalate on:  ├─ (a) anomaly detected                   │
                                     ├─ (b) random sample  ───► TEACHER confirm┘
                                     └─ (c) behavioural change      │
                                                                    ▼
                                                              LLM verdict / alert
```

### Prior art it builds on (do not over-claim)

- **Knowledge distillation / teacher-student models** — train/profile with a large model, deploy a small one. Established.
- **UEBA behavioural baselining** (Splunk UBA, Microsoft/Azure Sentinel, Exabeam) — learn per-entity "normal" over a baseline period, then score deviation cheaply. Established.
- **Cascade / triage / early-exit detection** — coarse-to-fine escalation. Established.

The combination (tiered enrollment → distilled always-on student → three-trigger re-escalation, applied to **service-category transition sequences**) is the engineering contribution.

### Why it resists the classic failure modes

- **Poisoning during enrollment** (attacker present or dormant during the baseline period → certified as "normal"): mitigated because certification is **not** trusted indefinitely. Any anomaly the student detects returns the host to the teacher, and **random sampling** re-verifies "trusted" hosts unpredictably — so lying low during enrollment does not buy permanent reduced scrutiny.
- **Window-wait bypass** (wait out a fixed retention/enrollment window): mitigated by random sampling, which has no schedule to wait out.
- **Concept drift** — treated as **two distinct problems**:
  - *Behavioural drift* of an individual host (new role, new tooling, new hours) → handled by **rolling re-enrollment**.
  - *Taxonomy drift* (new domains/services appear) → handled by **threat-intel scrapers** updating the Service Category Resolver.

### The three knobs (the honest tradeoff, made explicit)

| Knob | Increases | At the cost of |
| --- | --- | --- |
| **Sampling rate** of random re-escalation | Poison resistance | Compute |
| **Re-enrollment cadence** | Drift resistance | Compute |
| **Student sensitivity threshold** | Catch rate | False positives / re-escalation frequency |

### Residual risks (kept honest)

- **The student is the system ceiling.** It is the always-on layer that decides when to re-escalate; a subtle attack it cannot notice is never sent back to the teacher.
- **Activation → first-detectable-flaw latency.** Dormant-then-active malware is only caught once it does something the student can see — an inherent exposure window for any anomaly detector.
- **Lower purchased tiers are softer targets** (shorter enrollment, lower sampling). Commercially normal; do not market tiers as equally safe.
- **Scope monitoring by data sensitivity, not pay grade.** Attackers deliberately enter through low-privilege footholds (contractors, helpdesk); watching low-value accounts *less* optimizes the exact blind spot they exploit, and pay-grade-based surveillance is an HR/legal/privacy hazard.

### Open research question

*How cheap can the distilled student get while staying sensitive enough that re-escalation fires on real attacks but not on benign drift?* This is a knowledge-distillation quality question (student VRAM/latency vs. detection recall) and is the most publishable part of the work — alongside the chain-level, multi-service LSA provenance dataset, for which no public benchmark currently exists.
