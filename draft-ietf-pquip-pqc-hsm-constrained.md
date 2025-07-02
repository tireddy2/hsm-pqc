---
title: "Adapting Constrained Devices for Post-Quantum Cryptography"
abbrev: "Adapting Constrained Devices for PQC"
category: info

docname: draft-ietf-pquip-pqc-hsm-constrained
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "PQUIP"
keyword:
 - PQC
 - IoT
 - TEE
 - HSM
 - RoT


venue:
  group: "pquip"
  type: "Working Group"
  mail: "pqc@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/pqc/"


stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "k.tirumaleswar_reddy@nokia.com"
 -
    fullname: Dan Wing
    organization: Cloud Software Group Holdings, Inc.
    abbrev: Cloud Software Group
    country: United States of America
    email: danwing@gmail.com
 -
    fullname: Ben Salter
    organization: UK National Cyber Security Centre
    email: ben.s3@ncsc.gov.uk
 -
    fullname: Kris Kwiatkowski
    organization: PQShield
    email: kris@amongbytes.com

normative:

informative:
  RFC8554:
  RFC8391:
  ML-KEM:
     title: "FIPS-203: Module-Lattice-based Key-Encapsulation Mechanism Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
     date: false
  ML-DSA:
     title: "FIPS-204: Module-Lattice-Based Digital Signature Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
     date: false
  REC-SHS:
     title: "Recommendation for Stateful Hash-Based Signature Scheme"
     target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf
     date: false
  BIND:
    title: Unbindable Kemmy Schmid
    target: https://eprint.iacr.org/2024/523.pdf
  SLH-DSA:
     title: "FIPS-205: Stateless Hash-Based Digital Signature Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
     date: false
  FN-DSA:
     title: "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU"
     target: https://falcon-sign.info/falcon.pdf
     date: false
  Stream-SPHINCS:
     title: "Streaming SPHINCS+ for Embedded Devices using the Example of TPMs"
     target: "https://eprint.iacr.org/2021/1072.pdf"
     date: false
  BosRS22:
     title: "Dilithium for Memory Constrained Devices"
     target: "https://eprint.iacr.org/2022/323.pdf"
     date: false
  REC-KEM:
    title: Recommendations for Key-Encapsulation Mechanisms
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.ipd.pdf

--- abstract

This document offers guidance on incorporating Post-Quantum Cryptography (PQC) into
resource-constrained devices, including IoT devices and lightweight Hardware Security
Modules (HSMs), which operate under tight limitations on compute power, memory, storage,
and energy. It highlights how the Root of Trust acts as the foundation for secure operations,
enabling features such as seed-based key generation to reduce the need for persistent storage,
efficient approaches to managing ephemeral keys, and methods for offloading cryptographic tasks
in low-resource environments. Additionally, it examines how PQC affects firmware update
mechanisms in such constrained systems.

--- middle

# Introduction

The transition to post-quantum cryptography introduces significant challenges for
resource-constrained devices such as IoT devices, lightweight HSMs, secure elements (e.g.,
SIMs), and Trusted Execution Environments (TEEs). These devices often operate with limited
memory, non-volatile storage, processing power, and battery life, making the adoption of
PQC algorithms which typically involve larger key sizes and are more computationally
intensive than traditional algorithms particularly challenging. The increased key sizes
and computational demands of PQC require careful consideration to ensure secure and
efficient key management within these constrained environments.

This document provides industry guidance and best practices for integrating PQC algorithms
into constrained devices. It explores key storage strategies, ephemeral key management,
and performance optimizations specific to resource-limited environments. One approach to
mitigating storage constraints is seed-based key generation, where only a small seed is
stored instead of the full private key, as supported by PQC schemes like ML-DSA and
SLH-DSA. However, this technique increases computational overhead due to the need to derive
full private keys on demand,  a classic computation-versus-storage tradeoff. The document
also discusses considerations for ephemeral key generation in protocols like TLS and
IPsec, along with techniques to optimize PQC signature operations to enhance performance
within constrained crytographic modules.

This document focuses on the use of PQC algorithms in constrained devices, specifically
the three algorithms finalized by NIST: ML-DSA, ML-KEM, and SLH-DSA. While other PQC
algorithms, such as stateful hash-based signatures, also provide post-quantum security,
they are not covered in this version of the document. Future revisions may expand the
scope to include additional PQC algorithms.

# Key Management in Constrained Devices for PQC
The embedded cryptographic components used in constrained devices are designed to securely manage cryptographic keys, often under strict limitations in memory, storage capacity, and computational resources. These limitations are further exhausted by the increased key sizes and computational demands of PQC algorithms.

One mitigation of storage limitations is to store only the seed rather than the full
expanded private key, as the seed is far smaller and can derive the expanded private key
as necessary.

## Seed Management {#Seed}

The seed generated during the PQC key generation function is highly sensitive, as it will
be used to compute the private key or decapsulation key. Consequently, seeds must be
treated with the same level of security as private keys.

To comply with {{ML-KEM}}, {{ML-DSA}}, {{SLH-DSA}} and {{REC-KEM}} guidelines:

### Seed Storage

Some PQ key exchange mechanisms use a seed to generate their private keys (e.g., ML-KEM,
McEliece, and HQC), and those seeds are smaller than private keys, saving storage space.
Some implementations may choose to retain the (small) seed rather than the (larger)
private key.  As the private key is necessary for cryptographic operations, it can
be derived from the seed when needed or retained in a cache within the security module.

   Seeds must be securely stored within a cryptographic module of the device whether
hardware or software-based to protect against unauthorized access. Since the seed can derive
the private key, it must be safeguarded with the same
level of protection as a private key. For example, according to {{ML-DSA}}
Section 3.6.3, the seed ξ generated during ML-DSA.KeyGen can be stored for later use with
ML-DSA.KeyGen_internal.

   The choice between storing a seed or an expanded private key involves trade-offs
between storage efficiency and performance. Some constrained cryptographic modules may
store only the seed and derive the expanded private key on demand, whereas others may
prefer storing the full expanded key to reduce computational overhead during key usage.

   While vulnerabilities like the "Unbindable Kemmy Schmidt" attack {{BIND}} demonstrate
the risks of manipulating expanded private keys in environments lacking hardware-backed
protections, these attacks generally assume an adversary has some level of control over
the expanded key format. However, in a hardware-backed protcted environment, where private
keys are typically protected from such manipulation, the primary motivation for storing
the seed rather than the expanded key is not directly tied to mitigating "Kemmy" attacks.

   The ML-DSA and ML-KEM private key formats, as specified in
{{?I-D.ietf-lamps-dilithium-certificates}} and {{?I-D.ietf-lamps-kyber-certificates}},
represent the private key using a seed from which the expanded private key is derived.
While these formats rely on the seed for key generation, an constrained cryptographic
module may choose to store the expanded private key to avoid the additional computation
required for running KeyGen.

   This choice between storing the seed or the expanded private key has direct
implications on performance, as key derivation incurs additional computation. The impact
of this overhead varies depending on the algorithm. For instance, ML-DSA key generation,
which primarily involves polynomial operations using the Number Theoretic Transform (NTT)
and hashing, is computationally efficient compared to other post-quantum schemes. In
contrast, SLH-DSA key generation requires constructing a Merkle tree and multiple calls to
Winternitz One-Time Signature (WOTS+) key generation, making it significantly slower due
to the recursive hash computations involved. Designers of constrained systems must
carefully balance storage efficiency and computational overhead based on system
requirements and operational constraints. While constrained systems employ various key
storage strategies, the decision to store full private keys or only seeds depends on
design goals, performance considerations, and standards compliance (e.g., PKCS#11).

   A challenge arises when importing an existing private key into a system designed to
store only seeds. When a user attempts to import an already expanded private key, there is
a mismatch between the key format used internally (seed-based) and the expanded private
key. This issue arises because the internal format is designed for efficient key storage
by deriving the private key from the seed, while the expanded private key is already fully
computed. As NIST has not defined a single private key format for PQC algorithms, this
creates a potential gap in interoperability.

   If the seed is not securely stored at the time of key generation, it is permanently
lost because the process of deriving an expanded key from the seed relies on a one-way
cryptographic function. This one-way function derives the private key from the seed, but the reverse operation,
deriving the original seed from the expanded key is computationally infeasible.

### Efficient Key Derivation

   When storing only the seed in a constrained cryptographic module, it is crucial that
the device is capable of deriving the private key efficiently whenever required. However,
it is important to note that constantly re-deriving the private key for every
cryptographic operation may introduce significant performance overhead. In scenarios where
performance is a critical consideration, it may be more efficient to store the expanded
private key directly instead of only the seed. Higher quality implementations may also
retain (cache) recently-used or frequently-used private keys to avoid the computational
overhead and delay of deriving the private key from the seed with each request.

   The key derivation process, such as ML-KEM.KeyGen_internal for ML-KEM or similar
functions for other PQC algorithms, must be implemented in a way that can securely operate
within the resource constraints of the device. If using the seed-only model, the derived
private key should only be temporarily held in memory during the cryptographic operation
and discarded immediately after use. However, storing the expanded private key may be a
more practical solution in time-sensitive applications or for devices that frequently
perform cryptographic operations.

### Exporting Seeds and Private Keys

   Given the potential for hardware failures or the end-of-life of devices containing keys, it
is essential to plan for backup and recovery of the cryptographic seeds and private keys. Constrained
devices should support secure seed backup mechanisms, ideally leveraging encrypted storage
and ensuring that the backup data is protected from unauthorized access. In a disaster
recovery scenario, the seeds and private keys should be recoverable private key, provided the proper security measures are in place to prevent unauthorized
extraction.

   For secure exporting of seeds and private keys, AES-256 (or higher) should be
used to encrypt the seed before export. This ensures that the seed remains protected even
if the export process is vulnerable to quantum attacks.

Operationally, the exported data and the AES key should both be
protected against unauthorized access or modification.

   The encryption and the decryption of the seeds and private keys should remain entirely within the cryptographic
modules, to minimizes the risk of exposure and ensures compliance with established
security guidelines.

# Ephemeral Key Management

In protocols like TLS and IPsec, ephemeral keys are used for key exchange. Given the
increased size of PQC key material, ephemeral key management will have to be optimized for
both security and performance.

For PQC KEMs, ephemeral key-pairs are generated from an ephemeral seed, that is used
immediately during key generation and then discarded. Furthermore, once the shared secret is
derived, the private key will have to be deleted. Since the private key resides in the
constrained cryptographic module, removing it optimizes memory usage, reducing the footprint of
PQC key material in the cryptographic module. This ensures that that no unnecessary secrets
persist beyond their intended use.

Additionally, ephemeral keys, whether from traditional ECDH or PQC KEM algorithms are intended
to be unique for each key exchange instance and kept separate across connections (e.g., TLS).
Deleting ephemeral keying material after use not only optimizes memory usage but also ensures
that key material cannot be reused across connections, which would otherwise introduce security and
privacy issues. These risks are discussed in more detail in the Security Considerations of
{{?I-D.ietf-tls-hybrid-design}}.

Constrained devices implementing PQC ephemeral key management will have to:

  * Generate ephemeral key-pairs on-demand from an ephemeral seed stored temporarily within the cryptographic module.
  * Enforce immediate seed erasure after the key-pair is generated and the cryptographic operation is completed.
  * Delete the private key after the shared secret is derived.
  * Prevent key reuse across different algorithm suites or sessions.

# Optimizing Performance in Constrained Devices for PQC Signature Algorithms

When implementing PQC signature algorithms in constrained cryptographic modules,
performance optimization becomes a critical consideration. Transmitting the entire message
to the cryptographic module for signing can lead to significant overhead, especially for
large payloads. To address this, implementers can leverage techniques that reduce the data
transmitted to the cryptographic module, thereby improving efficiency and scalability.

One effective approach involves sending only a message digest to the cryptographic module
for signing. By signing the digest of the content rather than the entire content, the
communication between the application and the cryptographic module is minimized, enabling
better performance. This method is applicable for any PQC signature algorithm, whether it
is ML-DSA, SLH-DSA, or any future signature scheme. For such algorithms, a mechanism is
often provided to pre-hash or process the message in a way that avoids sending the entire
raw message for signing. In particular, algorithms like SLH-DSA present challenges due to
their construction, which requires multiple passes over the message digest during the
signing process. The signer does not retain the entire message or its full digest in
memory at once. Instead, different parts of the message digest are processed sequentially
during the signing procedure. This differs from traditional algorithms like RSA or ECDSA,
which allow for more efficient processing of the message, without requiring multiple
passes or intermediate processing of the digest.

A key consideration when deploying ML-DSA in cryptographic module is the amount of memory
available. ML-DSA, unlike traditional signature schemes such as RSA or ECDSA, requires
significant memory during signing due to multiple Number Theoretic Transform (NTT)
operations, matrix expansions, and rejection sampling loops. These steps involve storing
large polynomial vectors and intermediate values, making ML-DSA more memory-intensive. If
an cryptographic module has sufficient memory, this may not be an issue. However, in
constrained environments with limited memory, implementing ML-DSA can be challenging. The
signer must store and process multiple transformed values, leading to increased
computational overhead if the cryptographic module lacks the necessary memory to manage
these operations efficiently.

To address the memory consumption challenge, algorithms like ML-DSA offer a form of
pre-hash using the mu (message representative) value described in Section 6.2 of {{ML-DSA}}.
The mu value provides an abstraction for pre-hashing by allowing the hash or message
representative to be computed outside the cryptographic module. This feature offers
additional flexibility by enabling the use of different cryptographic modules for the
pre-hashing step, reducing memory consumption within the cryptographic module.
The pre-computed mu value is then supplied to the cryptographic module, eliminating the need to
transmit the entire message for signing. {{?I-D.ietf-lamps-dilithium-certificates}}
discusses leveraging ExternalMu-ML-DSA, where the pre-hashing step
(ExternalMu-ML-DSA.Prehash) is performed in a software cryptographic module, and only the
pre-hashed message (mu) is sent to the hardware cryptographic module for signing
(ExternalMu-ML-DSA.Sign). By implementing ExternalMu-ML-DSA.Prehash in software and
ExternalMu-ML-DSA.Sign in an hardware cryptographic module, the cryptographic workload
is efficiently distributed, making it practical for high-volume signing operations even
in memory-constrained cryptographic modules.

The main advantage of this method is that, unlike HashML-DSA, the ExternalMu-ML-DSA approach
is interoperable with the standard version of ML-DSA that does not use pre-hashing. This means
a message can be signed using ML-DSA.Sign, and the verifier can independently compute mu and use
ExternalMu-ML-DSA.Verify for verification -- or vice versa. In both cases, the verifier
does not need to know whether the signer used internal or external pre-hashing, as the resulting
signature and verification process remain the same.

# Additional Considerations for PQC Use in Constrained Devices

Key Rotation and Renewal: In constrained devices, managing the lifecycle of cryptographic
keys including periodic key rotation and renewal is critical for maintaining long-term
security and supporting cryptographic agility. While constrained devices may rely on
integrated secure elements or lightweight HSMs for secure key storage and operations, the
responsibility for orchestrating key rotation typically resides in the application layer
or external device management infrastructure.

Although the underlying cryptographic module may offer primitives to securely generate new
key pairs, store fresh seeds, or delete obsolete keys, these capabilities must be
integrated into the device’s broader key management framework. This process is especially
important in the context of PQC, where evolving research may lead to changes in
recommended algorithms, parameters, and key management practices.

The security of PQC schemes continues to evolve, with potential risks arising from
advances in post-quantum algorithms, cryptanalytic or implementation vulnerabilities. As a
result, constrained devices should be designed to support flexible and updatable key
management policies. This includes the ability to:

* Rotate keys periodically to provide forward-secrecy,

* Update algorithm choices or key sizes based on emerging security guidance,

* Reconfigure cryptographic profile of the device via firmware updates.

## Key Sizes of Post-Quantum Algorithms {#sec-key-sizes}

The key sizes of post-quantum algorithms are generally larger than those of traditional
cryptographic algorithms. This increase in key size is a significant consideration for
constrained devices, which often have limited memory and storage capacity. For example,
the key sizes for ML-DSA and ML-KEM are larger than those of RSA or ECDSA, which can lead to
increased memory usage and slower performance in constrained environments.

The following table provides the key sizes of some instantiations of ML-DSA, ML-KEM, FN-DSA
and SLH-DSA. For comparision we also include the key sizes for X25519 and ED25519, which
are traditional schemes widely used in constrained environments.

| Algorithm          | Type             | Size (bytes)     |
|--------------------|------------------|------------------|
| ML-DSA/65          | Public Key       | 1952             |
|                    | Private Key      | 4032             |
|                    | Signature        | 3309             |
| SLH-DSA-SHA2-192s  | Public Key       | 48               |
|                    | Private Key      | 96               |
|                    | Signature        | 16224            |
| FN-DSA-512         | Public Key       | 897              |
|                    | Private Key      | 1281             |
|                    | Signature        | 666              |
| ML-KEM/768         | Public Key       | 1568             |
|                    | Shared Secret    | 32               |
| X25519             | Public Key       | 32               |
|                    | Shared Secret    | 32               |
| Ed25519            | Public Key       | 32               |
|                    | Signature        | 64               |

Full key sizes for ML-DSA, ML-KEM, FN-DSA and SLH-DSA are specified in {{ML-DSA}}, {{ML-KEM}}, {{FN-DSA}}
and {{SLH-DSA}} respectively.

# Post-quantum Firmware Upgrades for Constrained Devices

Constrained devices deployed in the field require periodic firmware upgrades to patch
security vulnerabilities, introduce new cryptographic algorithms, and improve overall
functionality. However, the firmware upgrade process itself can become a critical attack
vector if not designed to be post-quantum. If an adversary compromises the update
mechanism, they could introduce malicious firmware, undermining all other security
properties of the cryptographic modules. Therefore, ensuring a post-quantum firmware
upgrade process is critical for the security of deployed constrained devices.

CRQCs pose an additional risk by breaking traditional digital signatures (e.g., RSA,
ECDSA) used to authenticate firmware updates. If firmware verification relies on
traditional signature algorithms, attackers could generate forged signatures in the future
and distribute malicious updates.

## Post-quantum Firmware Authentication

To ensure the integrity and authenticity of firmware updates, constrained devices will
have to adopt PQC digital signature schemes for code signing. These algorithms must provide
long-term security, operate efficiently in low-resource environments, and be compatible with
secure update mechanisms, such as the firmware update architecture for IoT
described in {{!RFC9019}}.

The Software Updates for Internet of Things (SUIT) working group is defining mandatory-to-implement cryptographic algorithms in {{?I-D.ietf-suit-mti}}, which includes the use of HSS-LMS.

Recommended post-quantum algorithms include:

* HSS-LMS (Hierarchical Signature System - Leighton-Micali Signature): A hash-based signature scheme, providing
  long-term security and efficient key management for firmware authentication (see {{REC-SHS}}).

* XMSS (eXtended Merkle Signature Scheme): Another stateful hash-based signature scheme similar to HSS-LMS
  {{RFC8391}}. XMSS signatures are slightly shorter than HSS-LMS signatures for equivalent security. However, HSS-LMS provides performance advantages and HSS-LMS is considered
  simpler (see Section 10 of {{RFC8554}}).

Firmware images can be signed using one of these post-quantum algorithms before being
distributed to constraied devices. {{?I-D.wiggers-hbs-state}} discusses various strategies
for a correct state and backup management for stateful hash-based signatures.

Firmware images often have a long lifetime, requiring cryptographic algorithms that
provide strong security assurances over extended periods. ML-DSA is not included in this
list because it is a lattice-based signature scheme, making it susceptible to potential
advances in quantum and classical attacks on structured lattices. The long-term security
of ML-DSA depends on the continued hardness of lattice-based problems, which remain an
active area of research. In addition, since ML-DSA implementations are still maturing,
relying on hash-based signatures can be a more reliable and production-ready option
for firmware authentication where long-term cryptographic stability is critical.

Hash-based signature schemes may be preferable to ML-DSA for firmware authentication,
particularly in scenarios where long-term cryptographic stability is a critical
requirement. Schemes such as SLH-DSA, HSS-LMS, and XMSS are built on well-understood
hash functions, and their security does not rely on unproven assumptions like the
hardness of lattice problems.

While SLH-DSA benefits from being stateless and avoids the complexity of state management,
its large signature sizes make it less suitable for memory-constrained devices. In contrast,
HSS-LMS and XMSS offer significantly smaller signatures and can achieve efficient
verification times, making them more practical choices for constrained environments
where performance and memory usage are key concerns.

## Hybrid signature approaches

To enable secure migration from traditional to post-quantum security, hybrid signature methods can be used for
firmware authentication. Parallel signatures, where a traditional and a post-quantum signature are generated and
attached separately, is simple to implement, requires minimal changes to existing signing, and aligns well with
current secure boot and update architectures.

Other hybrid techniques, such as cross-linked signatures (where signatures cover each other's values), composite signatures (which combine multiple signatures into a single structured signature), or counter-signatures (where one signature signs over another) introduce more complexity and are not yet typical in resource-constrained firmware workflows.

# Impact of PQC Authentication on Constrained Devices

In constrained environments, devices are typically assumed to function as clients that initiate outbound connections,
authenticating to servers using certificates or raw public keys ({{!RFC7250}}). However, some devices also serve in
server roles, enforcing local authentication policies. These scenarios require support for both outbound and inbound
authentication, and both roles face significant challenges when adopting post-quantum cryptography (PQC). Additionally,
verifying digital signatures such as during secure boot or firmware updates is a critical operation for constrained devices,
regardless of whether they act as clients or servers.

While specific deployment scenarios may differ, the fundamental technical impacts of PQC authentication in constrained devices can be summarized into three main areas:

* Larger Signatures and Certificate Sizes

   Post-quantum signature schemes typically produce much larger public keys and signatures than their traditional
   counterparts. A comparison is provided in [PQC key sizes](#sec-key-sizes).

   These larger artifacts introduce several challenges. For example, certificate chains with PQC public keys
   require more storage, and trust anchors - particularly for schemes like SLH-DSA - may be too large to embed in
   constrained ROM.

   Furthermore, validating signed payloads or commands increases network bandwidth requirements. In the case of large
   hash-based signatures, implementations may adopt streaming verification, where only parts of the message are
   processed at a time to reduce memory usage. An example of such an approach for SLH-DSA is described in
   {{Stream-SPHINCS}}.

* Increased RAM usage and performance profile.

   Post-quantum signature verification often demands significantly more RAM than traditional schemes used for
   asymmetric cryptography. For example, ML-DSA-65 in its high-performance configuration may require over 68 KB of
   memory during signing and up to 10 KB during verification on Cortex-M4-class devices.

   This poses challenges for use cases such as firmware verification (e.g. secure boot) and certificate validation
   during TLS handshakes or the generation of signed claims about the devices's hardware and software state, a process generally referred
   to as device attestation. As part of this remote attestation procedure {{!RFC9334}}, the device will need to present such claims
   to a remote peer, signed using an attestation key. To remain secure against CRQCs, the attestation mechanism must also
   employ quantum-safe cryptographic primitives.
   
   Several memory-optimized implementations exist (see {{BosRS22}}), but they typically trade memory savings for
   slower performance. For instance, the ML-DSA.Sign operation can be implemented within 8 KB of RAM, though at
   the cost of significantly increased runtime. Conversely, ML-DSA.Verify can be performed in as little as 3 KB of
   RAM without a major performance penalty.

   Devices with 8 - 16 KB of available RAM must often balance performance against feasibility when integrating PQC
   signature verification.

When constrained devices must authenticate inbound connections, validate commands, or verify stored data, PQC authentication
imposes a burden that must be explicitly addressed through selection of schemes with smaller signature sizes (e.g. FN-DSA).
These choices should be aligned with the device’s operational profile, available memory, and longevity requirements.

# Security Considerations

The security considerations for key management in constrained devices for PQC focus on the
secure storage and handling of cryptographic seeds, which are used to derive private keys.
Seeds must be protected with the same security measures as private keys, and key
derivation should be efficient and secure within resource-constrained cryptographic
module. Secure export and backup mechanisms for seeds are essential to ensure recovery in
case of hardware failure, but these processes must be encrypted and protected from
unauthorized access.

## Side Channel Protection
Side-channel attacks exploit physical leaks during cryptographic operations, such as timing information, power consumption, electromagnetic emissions, or other physical characteristics, to extract sensitive data like private keys or seeds. Given the sensitivity of the seed and private key in PQC key generation, it is critical to consider side-channel protection in cryptographic module design. While side-channel attacks remain an active research topic, their significance in secure hardware design cannot be understated. Cryptographic modules must incorporate strong countermeasures against side-channel vulnerabilities to prevent attackers from gaining insights into secret data during cryptographic operations.

# Acknowledgements
{:numbered="false"}

Thanks to Jean-Pierre Fiset, Richard Kettlewell, Mike Ounsworth, and Aritra Banerjee for
the detailed review.
