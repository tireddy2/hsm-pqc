---
title: "Adapting Constrained Devices for Post-Quantum Cryptography"
abbrev: "Adapting Constrained Devices for PQC"
category: info

docname: draft-ietf-pquip-pqc-hsm-constrained-latest
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
    organization: Citrix
    abbrev: Citrix
    country: United States of America
    email: "danwing@gmail.com"

 -
    fullname: Ben Salter
    organization: UK National Cyber Security Centre
    email: "ben.s3@ncsc.gov.uk"
 -
    fullname: Kris Kwiatkowski
    organization: PQShield
    email: "kris@amongbytes.com"

normative:

informative:
  FIPS203: DOI.10.6028/NIST.FIPS.203
  FIPS204: DOI.10.6028/NIST.FIPS.204
  FIPS205: DOI.10.6028/NIST.FIPS.205
  SP800-208: DOI.10.6028/NIST.SP.800-208
  ISO19790:
    title: "Information security, cybersecurity, and privacy protection - Security requirements for cryptographic modules"
    target: https://www.iso.org/standard/82423.html
    author:
      - org: ISO
    date: February 2025
  BIND:
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    target: https://eprint.iacr.org/2024/523.pdf
    author:
      - ins: S. Schmieg
    date: April 2024
  HQC:
     title: "Hamming Quasi-Cyclic (HQC)"
     target: https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf
     author:
       - ins: Gaborit et al.
     date: August 2025
  Falcon:
     title: "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU"
     target: https://falcon-sign.info/falcon.pdf
     author:
     - ins: P-A. Fouque
     - ins: J. Hoffstein
     - ins: P. Kirchner
     - ins: V. Lyubashevsky
     - ins: T. Pornin
     - ins: T. Prest
     - ins: T. Ricosset
     - ins: G. Seiler
     - ins: W. Whyte
     - ins: Z. Zhang
     date: October 2020
  Stream-SPHINCS:
     title: "Streaming SPHINCS+ for Embedded Devices using the Example of TPMs"
     target: https://eprint.iacr.org/2021/1072.pdf
     author:
     - ins: R. Niederhagen
     - ins: J. Roth
     - ins: J. Walde
     date: August 2021
  BosRS22:
     title: "Dilithium for Memory Constrained Devices"
     target: https://eprint.iacr.org/2022/323.pdf
     author:
       - ins: J. Bos
       - ins: J. Renes
       - ins: A. Sprenkels
     date: December 2022
  REC-KEM: DOI.10.6028/NIST.SP.800-227
  Lyu09: DOI.10.1007/978-3-642-10366-7_35
  Li32:
     title: "CRYSTALS-Dilithium: Algorithm Specifications and Supporting Documentation (Version 3.1)"
     target: https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
     author:
     - ins: S. Bai
     - ins: L. Ducas
     - ins: E. Kiltz
     - ins: T. Lepoint
     - ins: V. Lyubashevsky
     - ins: P. Schwabe
     - ins: G. Seiler
     - ins: D. Stehle
     date: February 2021
  NISTSecurityCategories:
    title: "Post-Quantum Cryptography: Security (Evaluation Criteria)"
    target: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)
    author:
    - org: NIST
    date: January 2017
  Bot19:
     title: "Memory-Efficient High-Speed Implementation of Kyber on Cortex-M4"
     target: https://eprint.iacr.org/2019/489.pdf
     author:
       - ins: L. Botros
       - ins: M. J. Kannwischer
       - ins: P. Schwabe
     date: May 2019
  Gre20: DOI.10.46586/tches.v2021.i1.1-24
  Smaller-SPHINCS:
    title: "Smaller Sphincs+ or, Honey, I Shrunk the Signatures"
    target: https://eprint.iacr.org/2024/018.pdf
    author:
      - ins: S. Fluhrer
      - ins: Q. Dang
    date: January 2024
  IEEE802.1AR:
    title: "IEEE Standard for Local and Metropolitan Area Networks - Secure Device Identity"
    target: https://standards.ieee.org/ieee/802.1AR/6995/
    seriesinfo:
      IEEE: "802.1AR-2018"
    author:
      - org: IEEE
    date: 2018
  KWI2026:
   title: "The Rejection Rate of ML-DSA Signing: Correcting FIPS-204"
   target: https://amongbytes.com/posts/rejection-rate-of-mldsa-signing
   author:
     - ins: K. Kwiatkowski
   date: October 2026
  FIPS204_errata:
   title: "FIPS 204 - Potential Updates (Errata)"
   target: "https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx"
   author:
   - org: NIST
   date: July 2026


--- abstract

This document provides guidance on integrating Post-Quantum Cryptography (PQC) into
resource-constrained devices, such as IoT nodes and dedicated key-storage hardware.
These systems often operate with strict limitations on processing power, RAM, and
flash memory, and may even be battery-powered. The document emphasizes the role of hardware
security as the basis for secure operations, supporting features such as seed-based key
generation to minimize persistent storage, efficient handling of ephemeral keys, and the
offloading of cryptographic tasks in low-resource environments. It also explores the
implications of PQC on firmware update mechanisms in such constrained systems.

--- middle

# Introduction

The transition to post-quantum cryptography (PQC) poses significant challenges for
resource-constrained devices, such as dedicated key-storage hardware and
Internet of Things (IoT) devices.

These devices typically operate under strict limitations on
processing power, RAM, and flash memory, and in some cases are battery-powered. Adopting
PQC algorithms in such environments is difficult due to their substantially larger key
sizes and, in some cases, higher computational demands. Consequently, the migration to
PQC requires careful planning to ensure secure and efficient key management within
constrained platforms.

Constrained devices are often deployed as clients initiating outbound connections, but some also act in server roles or enforce local authentication policies.
As a result, designers may need to consider PQC to address confidentiality, both outbound and inbound authentication, and signature verification used in secure boot, firmware updates, and device attestation.

This document provides guidance and best practices for integrating PQC algorithms into
constrained devices. It reviews strategies for key storage, ephemeral key management,
and performance optimization tailored to low-resource environments. The document also
examines ephemeral key generation in protocols such as TLS, along with techniques to
optimize PQC signature operations to improve performance within constrained cryptographic
modules.

This document focuses on PQC algorithms standardized by NIST or specified by the IRTF CFRG, and that have corresponding IETF protocol specifications, either published as RFCs or progressing through the IETF standards process. Specifically, it covers the following algorithms:

- Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) {{FIPS203}}.
- Module-Lattice-Based Digital Signature Algorithm (ML-DSA) {{FIPS204}}.
- Stateless Hash-Based Digital Signature Algorithm (SLH-DSA) {{FIPS205}}.

- Hierarchical Signature System/Leighton-Micali Signature (HSS/LMS) {{?RFC8554}}, and the related eXtended Merkle Signature Scheme (XMSS) {{?RFC8391}}.

Additional post-quantum algorithms are expected to be standardised in future, which may also prove suitable for use in constrained devices. Since algorithms may change prior to standardisation (or may end up unstandardised), no concrete guidance is provided on these here, but future specifications may provide guidance on the following algorithms:

- The Falcon signature scheme {{Falcon}} has shorter keys and signatures than ML-DSA, though its use of floating point arithmetic may make it challenging to implement on some devices.
- The HQC KEM {{HQC}} is a code-based KEM, so offers algorithmic diversity to complement lattice-based KEMs, though it is less performant than ML-KEM.
- Smaller SLH-DSA parameter sets {{Smaller-SPHINCS}} may be standardised in future, which may make use of SLH-DSA more palatable on constrained devices.

This document focuses on device-level adaptations and considerations necessary to implement PQC efficiently on constrained devices.
Actual protocol behaviour is defined in other documents.

# Key Management in Constrained Devices for PQC

The embedded cryptographic components used in constrained devices are designed to securely manage cryptographic keys, often under strict limitations in RAM, flash memory, and computational resources. These limitations are further exhausted by the increased key sizes and computational demands of PQC algorithms.

One mitigation of storage limitations is to store only the seed rather than the full
expanded private key, as the seed is far smaller and can derive the expanded private key
as necessary. {{FIPS204}} Section 3.6.3 specifies that the seed &xi; generated during ML-DSA.KeyGen can be stored for later use with ML-DSA.KeyGen_internal.
To reduce storage requirements on constrained devices, private keys for
Initial Device Identifiers (IDevIDs) and Locally Significant Device
Identifiers (LDevIDs) {{IEEE802.1AR}}, and the optional attestation private key can be
stored as seeds instead of expanded key material.

## Seed Management {#Seed}

The following is some additional guidance to aid in compliance with {{FIPS203}}, {{FIPS204}}, {{FIPS205}} and {{REC-KEM}}:

### Seed Storage

Several post-quantum algorithms use a seed to generate their private keys (e.g., ML-KEM and ML-DSA). Those seeds are smaller than private keys, hence some implementations may choose to retain the seed rather than the full private key to save on storage space. The private key can then be derived from the seed when needed or retained in a cache within the security module.

The seed is a Critical Security Parameter (CSP) as defined in {{ISO19790}}, from which the private key can be derived, hence it must be safeguarded with the same
level of protection as a private key. Seeds should be securely stored within a cryptographic module of the device whether hardware or software-based to protect against unauthorized access.

   The choice between storing a seed or an expanded private key involves trade-offs
between storage efficiency and performance. Some constrained cryptographic modules may
store only the seed and derive the expanded private key on demand, whereas others may
prefer storing the full expanded key to reduce computational overhead during key usage.

   The choice between storing the seed or the expanded private key has direct
implications on performance, as key derivation incurs additional computation. The impact
of this overhead varies depending on the algorithm. For instance, ML-DSA key generation,
which primarily involves polynomial operations using the Number Theoretic Transform (NTT)
and hashing, is computationally efficient compared to other post-quantum schemes. In contrast,
SLH-DSA key generation requires constructing a Merkle tree and multiple Winternitz One-Time
Signature (WOTS+) key generations, making it significantly more computationally intensive. In
many embedded deployments, SLH-DSA is expected to be used primarily for firmware verification.
In this case the device holds only the SLH-DSA public key; the corresponding private key is known
solely to the firmware signer, and key generation is performed on the signer's infrastructure
rather than on the device. Consequently, SLH-DSA key generation cost does not impact device
performance. However, in scenarios where the device generates its own SLH-DSA key pairs, the
higher key generation cost may influence seed-storage design decisions and depend on performance
considerations or standards compliance (e.g., PKCS#11).

   While vulnerabilities like the "Unbindable Kemmy Schmidt" misbinding attack {{BIND}} demonstrate
the risks of manipulating expanded private keys in environments lacking hardware-backed
protections, these attacks generally assume an adversary has some level of control over
the expanded key format. However, in a hardware-backed protected environment, where private
keys are typically protected from such manipulation, the primary motivation for storing
the seed rather than the expanded key is not directly tied to mitigating such misbinding attacks.

The expanded private key is derived from the seed using a one-way cryptographic function.
As a result, if the seed is not retained at key generation time, it cannot be reconstructed
from the expanded key (as the reverse operation is computationally infeasible). Implementations
should account for this non-recoverability when designing seed management.

   A challenge arises when importing an existing private key into a system designed to
store only seeds. When a user attempts to import an already expanded private key, there is
a mismatch between the key format used internally (seed-based) and the expanded private
key. This issue arises because the internal format is designed for efficient key storage
by deriving the private key from the seed, while the expanded private key is already fully
computed. As NIST has not defined a single private key format for PQC algorithms, this
creates a potential gap in interoperability.

### Efficient Key Derivation

   When storing only the seed in a constrained cryptographic module, it is crucial that
the device is capable of deriving the private key efficiently whenever required. However,
repeatedly re-deriving the private key for every
cryptographic operation may introduce significant performance overhead. In scenarios where
performance is a critical consideration, it may be more efficient to store the expanded
private key directly (in addition to the seed). Implementations may choose to
retain (cache) several recently-used or frequently-used private keys to avoid the computational
overhead and delay of deriving private keys from their seeds for each operation.

   The key derivation process, such as ML-KEM.KeyGen_internal for ML-KEM or similar
functions for other PQC algorithms, must be implemented in a way that can securely operate
within the resource constraints of the device. If using the seed-only model, the derived
private key should exist only transiently, held for the duration of the cryptographic operation,
and any state derived from it should be securely erased or otherwise made
unrecoverable as soon as it is no longer needed. However, storing the expanded private key may be a
more practical solution in time-sensitive applications or for devices that frequently
perform cryptographic operations.

### Exporting Seeds and Private Keys

   Given the potential for hardware failures or the end-of-life of devices containing keys, it
is essential to plan for backup and recovery of cryptographic seeds and private keys.
Constrained devices should support secure seed- or key-backup mechanisms, leveraging protections such as encrypted storage and ensuring that security measures are in place so that the backup data is protected from unauthorized access.

When exporting a seed or private key, the key-encryption key or the key protecting the secure channel used for direct transfer should provide a security strength at least matching the PQ security level of the exported key. Using the security level mapping in {{?RFC9958}}, Level 1 corresponds to AES-128, Level 3 to AES-192, and Level 5 to AES-256; for example, an ML-KEM-1024 or ML-DSA-87 key (Level 5) should be protected using AES-256.

There are two distinct approaches to exporting private keys or seeds from a constrained device:

#### Direct Transfer Over a Secure Channel {#direct-transfer}

In scenarios where the constrained device can establish a secure channel to a peer, the device can transfer encrypted private key material directly to another cryptographic module over that channel. The secure channel needs to provide mutual authentication of both endpoints, confidentiality and integrity protection of the transferred material, and end-to-end protection. A mutually authenticated TLS 1.3 {{?RFC9846}} connection is one example of a protocol providing these properties; DTLS 1.3 {{?RFC9147}} offers the same properties over datagram transport and may be more suitable for some constrained deployments.

Since private key material is a long-lived secret, its transfer is particularly exposed to the "harvest now, decrypt later" (HNDL) attack described above: an attacker records the protected traffic today and decrypts it once a CRQC is available. To mitigate this threat, the secure channel must be established with a key exchange that provides post-quantum security; for (D)TLS 1.3, this can be achieved with a hybrid key exchange combining ECDHE with ML-KEM {{?RFC10024}} or with a standalone ML-KEM key exchange {{?I-D.ietf-tls-mlkem}}. Post-quantum key exchange alone is sufficient to protect against HNDL, as authentication cannot be broken retroactively; however, once CRQCs are available, an attacker could impersonate an endpoint during channel establishment, so post-quantum authentication, e.g., with ML-DSA {{?I-D.ietf-tls-mldsa}}, should additionally be used.

#### Export of Encrypted Seeds and Private Keys {#encrypted-export}

In more common constrained device scenarios for secure exporting of seeds and private keys, a strong symmetric encryption algorithm, such as AES Key Wrap with Padding ({{!RFC5649}}), should be used to encrypt the seed or private key before export. {{!RFC5649}} adds padding to handle key material whose length is not a multiple of 8 octets, such as an expanded private key that does not fall on that boundary.

Operationally, the exported data and the symmetric key used for encryption must both be protected against unauthorized access or modification.

#### Security Requirements for Export Operations

The encryption and decryption of seeds and private keys must occur entirely within the cryptographic modules to reduce the risk of exposure and ensure compliance to established security standards.

## Ephemeral Key Management

Given the increased size of PQC key material, ephemeral key management will have to
be optimized for both security and performance.

For PQC KEMs, ephemeral key pairs are generated from an ephemeral seed, that is used
immediately during key generation and then discarded. Furthermore, once the shared secret is
derived, the ephemeral private key will have to be deleted. Since the private key resides in the
constrained cryptographic module, removing it optimizes memory usage, reducing the footprint of
PQC key material in the cryptographic module. This also ensures that that no unnecessary secrets
persist beyond their intended use.

Additionally, ephemeral keys, whether from traditional ECDH or PQC KEM algorithms, are intended
to be unique for each key exchange instance and kept separate across connections (e.g., TLS).
Deleting ephemeral keying material after use helps ensure that key material cannot be reused across connections, which would otherwise introduce security and privacy issues.

Constrained devices implementing PQC ephemeral key management will have to:

- Generate ephemeral key pairs on-demand from an ephemeral seed stored temporarily within the cryptographic module.
- Enforce immediate seed erasure after the key pair is generated and the cryptographic operation is completed.
- Delete the private key after the shared secret is derived.
- Prevent key reuse across different algorithm suites or sessions.

# Optimizing Memory Footprint in Post-Quantum Signature Schemes {#sig-mem}

A key consideration when deploying post-quantum cryptography in cryptographic modules is the amount and type of memory available. In constrained devices, it is important to distinguish between volatile memory (RAM), used for intermediate computations during cryptographic operations, and non-volatile storage (e.g., flash), used for storing keys, firmware, and configuration data. For instance, ML-DSA, unlike traditional signature schemes such as RSA or ECDSA, requires significant RAM during signing due to multiple Number Theoretic Transform (NTT) operations, matrix expansions, and rejection sampling loops. These steps involve storing large polynomial vectors and intermediate values, making ML-DSA more memory-intensive.

Some constrained systems, particularly battery-operated devices, may have limited RAM available for cryptographic operations, even if sufficient non-volatile storage is available. In such cases, straightforward implementations of PQ schemes may exceed available RAM, making them infeasible without optimization.

Several post-quantum schemes can be optimized to reduce the memory footprint of the algorithm. For instance, SLH-DSA has two flavors: the "f" variants which are parameterized to run as fast as possible, and the "s" variants which produce shorter signatures. Developers wishing to use SLH-DSA may wish to utilize the "s" variants on devices with insufficient RAM to use the "f" variants. Further optimizations may be possible by running the signature algorithm in a "streaming manner" such that constrained device does not need to hold the entire signature in memory at once, as discussed in {{Stream-SPHINCS}}.

Implementations may trade off resource usage across CPU, RAM, and non-volatile storage. For example, techniques such as lazy expansion reduce RAM usage at the cost of increased computation, while storing expanded key in non-volatile storage can reduce runtime overhead. Designers should balance these trade-offs based on the target platform.

Both the ML-KEM and ML-DSA algorithms were selected for general use. Two optimization techniques that can be applied to make ML-DSA more feasible in constrained cryptographic modules are discussed in {{lazy-expansion}} and {{pre-hashing}}.

## Memory requirements of Lattice-Based Schemes

Both ML-KEM and ML-DSA are built on the same lattice structure, and the dominant source of memory usage in either is holding the expanded matrix A and the associated polynomial vectors needed to compute a noisy affine transformation of the form t = A\*s + e, where A is a public matrix derived from a seed, and t, s and e are polynomial vectors. In ML-DSA this transformation is written t = A\*s1 + s2, with s1 and s2 being the secret polynomial vectors that are part of the private key and are used during signing. The elements of those matrices and vectors are polynomials with 256 integer coefficients modulo Q. ML-DSA uses a 23-bit modulus Q, so each coefficient is held in 4 bytes (`uint32`), whereas ML-KEM uses a 12-bit modulus and each coefficient is held in 2 bytes (`uint16`); in both cases the modulus is the same regardless of parametrization. The dimensions of the matrix and vectors, however, do depend on the parameter set.

The worked example below uses ML-KEM-768 rather than an ML-DSA parameter set, because its dimensions and coefficient size give smaller numbers that are easier to follow; the method of accounting carries over unchanged to ML-DSA. The public matrix A for ML-KEM-768 has dimensions 3x3, with each polynomial having 256 coefficients of 2 bytes each, leading to a size of 3\*3\*256\*2 = 4,608 bytes (approximately 4.5 KB) for the matrix A alone. The polynomial vectors t, s and e also contribute significantly to memory usage, with each vector requiring 3\*256\*2 = 1,536 bytes (approximately 1.5 KB). Hence, for a straightforward implementation, the amount of memory required is 4,608 + 3\*1,536 = 9,216 bytes (approximately 9 KB). The same computation can be done for other instantiations of ML-KEM as well as for ML-DSA. ML-DSA has much higher memory requirements, both because its matrices and vectors are larger and because each coefficient occupies 4 bytes rather than 2. For ML-DSA-87, where A has dimensions 8x7, signing holds A together with the private-key vectors s1, s2 and t0 of 7, 8 and 8 elements respectively. This gives 8\*7\*256\*4 = 57,344 bytes for A and a further 23\*256\*4 = 23,552 bytes for the vectors, so a straightforward implementation needs at least 79 KB of RAM during signing, before accounting for the per-iteration vectors such as y, w and z.

It is worth noting that different cryptographic operations may have different memory requirements. For example, during ML-DSA verification, the memory usage is lower since the private key components are not needed.

### Lazy Expansion as a Memory Optimization Technique {#lazy-expansion}

The lazy expansion technique is an optimization that significantly reduces memory usage by avoiding the need to store the entire expanded matrix A in memory at once. Instead of pre-computing and storing the full matrix, lazy expansion generates parts of it on-the-fly as needed for the process. This approach leverages the fact that not all elements of the matrix are required simultaneously, allowing for a more efficient use of memory.

As an example, we can look at the computation of matrix-vector multiplication t=A\*s. The matrix A is generated from a seed using an extendable-output function (XOF), meaning that any element of A can be computed independently when needed. Similarly, the vector s is expanded from a random seed and a nonce using a pseudo-random function (PRF).

Lazy expansion first generates the first element of the vector s (`s(0)`), then iterates over the rows of the first column of A, generating one element at a time and accumulating a partial result into t. It then generates `s(1)` and repeats the process for the next column, until all elements of s have been processed. For ML-KEM-768, each polynomial takes 512 bytes (256 coefficients of 2 bytes each), so only one element of s (512 bytes), one element of A (512 bytes) and the vector t (3\*512 = 1,536 bytes) need to be held in memory at any time, about 2.5 KB in total compared to approximately 9 KB for a straightforward implementation. The savings are even more pronounced for ML-DSA, where combining lazy expansion with keeping the private-key vectors in packed form reduces the memory required for signing from at least 79 KB to a small fraction of that; see {{Gre20}} and {{BosRS22}} for measured figures.

With lazy expansion, the implementation differs slightly from the straightforward version. Also, in some cases, lazy expansion may introduce additional computational overhead. Notably, applying it to ML-DSA signing may require computing the vector y ({{FIPS204}}, Algorithm 7, line 11) twice. In this case implementers need to weigh the trade-off between memory savings and additional computation.

This memory optimization was initially described in {{Bot19}}.

## Pre-hashing as a Memory Optimization Technique {#pre-hashing}

To address the memory consumption challenge, algorithms like ML-DSA offer a form of
pre-hash using the &mu; (message representative) value described in Section 6.2 of {{FIPS204}}.
The &mu; value provides an abstraction for pre-hashing by allowing the hash or message
representative to be computed outside the cryptographic module. This feature offers
additional flexibility by enabling the use of different cryptographic modules for the
pre-hashing step, reducing memory consumption within the cryptographic module.
The pre-computed &mu; value is then supplied to the cryptographic module, eliminating the need to
transmit the entire message for signing. {{?RFC9881}}
discusses leveraging External&mu;-ML-DSA, where the pre-hashing step
(External&mu;-ML-DSA.Prehash) is performed in a software cryptographic module, and only the
pre-hashed message (&mu;) is sent to the hardware cryptographic module for signing
(External&mu;-ML-DSA.Sign). By implementing External&mu;-ML-DSA.Prehash in software and
External&mu;-ML-DSA.Sign in an hardware cryptographic module, the cryptographic workload
is efficiently distributed, making it practical for high-volume signing operations even
in memory-constrained cryptographic modules.

The main advantage of this method is that, unlike HashML-DSA, the External&mu;-ML-DSA approach
is interoperable with the standard version of ML-DSA that does not use pre-hashing. This means
a message can be signed using ML-DSA.Sign, and the verifier can independently compute &mu; and use
External&mu;-ML-DSA.Verify for verification -- or vice versa. In both cases, the verifier
does not need to know whether the signer used internal or external pre-hashing, as the resulting
signature and verification process remain the same.

# Cryptographic Artifact Sizes for Post-Quantum Algorithms {#sec-key-sizes}

The sizes of keys, ciphertexts, and signatures of post-quantum algorithms are generally larger than those of traditional
cryptographic algorithms. This increase in size is a significant consideration for
constrained devices, which often have limited memory and storage capacity. For example,
the key sizes for ML-DSA and ML-KEM are larger than those of RSA or ECDSA, which can lead to
increased memory usage and slower performance in constrained environments.

{{artifact-size}} presents artifact sizes organized by NIST security categories published in
the initial call for proposals {{NISTSecurityCategories}}. The security categories are defined
as requiring computational resources comparable to or greater than an attack on AES (128, 192, and 256)
and SHA2/SHA3 algorithms, i.e., exhaustive key recovery for AES and optimal collision search for
SHA2/SHA3 schemes. The table lists the sizes of cryptographic artifacts for representative instantiations
of selected post-quantum cryptographic schemes of the lowest available security categories defined for
the respective schemes. X25519 and Ed25519 are included for comparison; they approximately map to NIST
Security Category 1 based on ~128-bit classical security, though this is not an official NIST designation.

| Level | Algorithm             | Type             | Size (bytes) |
|-------|-----------------------|------------------|--------------|
|   2   | ML-DSA-44             | Public Key       | 1312         |
|       |                       | Private Key      | 2560         |
|       |                       | Signature        | 2420         |
|   1   | SLH-DSA-SHA2-128s     | Public Key       | 32           |
|       |                       | Private Key      | 64           |
|       |                       | Signature        | 7856         |
|   1   | SLH-DSA-SHA2-128f     | Public Key       | 32           |
|       |                       | Private Key      | 64           |
|       |                       | Signature        | 17088        |
|   3   | LMS_SHA256_M24_H15_W4 | Public Key       | 48           |
|       |                       | Private Key      | 44           |
|       |                       | Signature        | 1620         |
|   3   | XMSS-SHA2_10_192      | Public Key       | 48           |
|       |                       | Private Key      | 104          |
|       |                       | Signature        | 1492         |
|   1   | ML-KEM-512            | Public Key       | 800          |
|       |                       | Private Key      | 1632         |
|       |                       | Ciphertext       | 768          |
|       |                       | Shared Secret    | 32           |
|   1*  | X25519                | Public Key       | 32           |
|       |                       | Private Key      | 32           |
|       |                       | Shared Secret    | 32           |
|   1*  | Ed25519               | Public Key       | 32           |
|       |                       | Private Key      | 32           |
|       |                       | Signature        | 64           |
{: #artifact-size title="Sizes of cryptographic artifacts"}

Corresponding sizes for higher security categories will typically be larger - see {{FIPS203}}, {{FIPS204}}, {{FIPS205}}, {{SP800-208}}, {{?RFC9858}} for sizes for all parameter sets.

# Optimizing Performance in PQC Signature Schemes {#sig-perf}

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
their construction, which requires two passes over the message during the
signing process. The signer must therefore either retain the message for the second pass
or receive it twice. This differs from traditional algorithms like RSA or ECDSA,
which allow for more efficient processing of the message, without requiring multiple
passes or intermediate processing of the digest.

## Impact of rejection sampling in ML-DSA Signing on performance {#mldsa-rej-sampling}

In constrained and battery-powered IoT devices that perform ML-DSA signing, the rejection-sampling
loop introduces variability in signing latency and energy consumption due to the probabilistic
nature of the signing process. While this results in a variable number of iterations in the signing
algorithm, the expected number of attempts for the standardized ML-DSA parameter sets is quantified
below.

The analysis in this section follows the algorithmic structure and assumptions defined in
{{FIPS204}}. The results characterize the expected behavior of ML-DSA rather than any particular
implementation.

The ML-DSA signature scheme uses the Fiat-Shamir with Aborts construction {{Lyu09}}. As a
result, the signature generation algorithm is built around a rejection-sampling loop. This
section examines the rejection-sampling behavior of ML-DSA, as rejection sampling is not
commonly used as a core mechanism in traditional digital signature schemes.

Rejection sampling is used to ensure that intermediate and output values follow the
distributions required by the security proof. In particular, after computing candidate signature
components, the signer checks whether certain norm bounds are satisfied. If any of these bounds
are violated, the entire signing attempt is discarded and restarted with fresh randomness.

The purpose of rejection sampling is twofold: First, it prevents leakage of information about the
secret key through out-of-range values that could otherwise bias the distribution of signatures.
Second, it ensures that the distribution of valid signatures is statistically close to the ideal
distribution assumed in the security reduction, namely the zero-knowledge property underlying the
reduction to the SelfTargetMSIS problem (see Section 6.2.1 of {{Li32}}).

The number of rejections during signature generation depends on three factors:

- the message representative &mu;, which depends on the message, the context string (see {{FIPS204}}, Section 5.2) and the public key
- the secret key material
- when hedged signing is used (see {{FIPS204}}, Section 3.4), the random seed

As a result, some message-key combinations may lead to a higher number of
rejection iterations than others.

Each signing attempt can be modeled as an independent Bernoulli trial: an attempt
either succeeds or is rejected, with a fixed per-attempt acceptance probability.
Under this assumption, the number of attempts until success follows a geometric
distribution, and the expected number of attempts is the reciprocal of the
acceptance probability.

The values below are taken from {{KWI2026}}, assuming a random bit generator
(RBG) as specified in {{FIPS204}} (Section 3.6.1).

| ML-DSA Variant | Per-attempt Acceptance | Expected Number of Attempts |
|----------------|------------------------|-----------------------------|
| ML-DSA-44      | 0.2293                 | 4.361                       |
| ML-DSA-65      | 0.1947                 | 5.137                       |
| ML-DSA-87      | 0.2561                 | 3.905                       |
{: #Expected_Attempts title="Per-attempt acceptance probability and expected number of attempts for the given ML-DSA variant."}

The cumulative distribution function (CDF) follows directly from the geometric
model. {{MLDSA_Sign_CDF}} shows, for each ML-DSA variant, the probability that
signing completes within a given number of iterations. The first rows matter
most in practice: more than half of all signing operations complete within 3
iterations (4 for ML-DSA-65).

| Iteration | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| 1         | 0.2293    | 0.1947    | 0.2561    |
| 2         | 0.4060    | 0.3514    | 0.4466    |
| 3         | 0.5423    | 0.4777    | 0.5883    |
| 4         | 0.6472    | 0.5794    | 0.6937    |
| 5         | 0.7281    | 0.6612    | 0.7722    |
| 6         | 0.7905    | 0.7272    | 0.8305    |
| 7         | 0.8385    | 0.7803    | 0.8739    |
| 8         | 0.8755    | 0.8231    | 0.9062    |
| 9         | 0.9041    | 0.8575    | 0.9302    |
| 10        | 0.9261    | 0.8852    | 0.9481    |
| 11        | 0.9430    | 0.9076    | 0.9614    |
| 12        | 0.9561    | 0.9256    | 0.9713    |
{: #MLDSA_Sign_CDF title="Probability of completing the signing process within the given number of iterations, for each ML-DSA variant."}

Inverting the CDF gives the minimum number of iterations n required to reach a
desired completion probability, n >= ln(1 - target) / ln(1 - p). This is the
figure implementations need when budgeting for worst-case latency or energy
rather than for the average case.

| Target | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|--------|-----------|-----------|-----------|
| 90%    | 9         | 11        | 8         |
| 95%    | 12        | 14        | 11        |
| 99%    | 18        | 22        | 16        |
{: #MLDSA_Sign_Quantiles title="Iterations required to reach a given probability of completing the signing process, for each ML-DSA variant."}

Every variant reaches at least 90% within 11 iterations, but the tail is long:
ML-DSA-65 needs 22 iterations for 99%, against an expected 5.1.

{{FIPS204}} Appendix C bounds the signing loop at 814 iterations for a
failure probability of at most 2^-256, based on the expected repetition
counts in {{FIPS204}} Table 1. A more precise computation of these counts
(see {{Expected_Attempts}}) gives 5.137 for ML-DSA-65, the parameter set
with the highest repetition count, which yields a limit of 820 iterations;
with 814, the probability that signing fails to complete is about
2^-254.2, slightly short of the 2^-256 target. This does not affect the
security of ML-DSA, as such a failure only requires signing to be
retried. The FIPS 204 potential updates {{FIPS204_errata}} also conclude
that 814 is too low, but compute the limit from the rounded count 5.14,
giving 821. This is one iteration above the minimum derived here, so it
also meets the 2^-256 target. For FIPS compliance, implementations that
bound the loop should use the limit specified in {{FIPS204}}, or in a
published update to it.

### Practical Implications for Constrained Cryptographic Modules

As shown above, the rejection-sampling loop in ML-DSA signing leads to a probabilistic runtime
with a geometrically distributed number of iterations. While the expected execution time is
small, the tail of the distribution implies that, with low probability, a signing operation
may require significantly more iterations than average. This unfavorable tail behavior represents
a practical concern for ML-DSA deployments on constrained devices with limited execution
capability and may require additional consideration.

As discussed in {{Seed}}, in many deployment scenarios, constrained devices primarily perform signature verification, while signature generation is performed on more capable systems (e.g., firmware signing infrastructure). Therefore, the impact of rejection sampling is primarily relevant for devices that perform ML-DSA signing.

Devices that only verify signatures are not affected, as those operations do not involve rejection sampling and have deterministic execution times.

In firmware update and secure boot scenarios, signature verification is typically performed during early boot stages, where the bootloader has exclusive access to system resources. In such environments, the practical impact of resource constraints on signature verification is reduced compared to general runtime environments.

Verification does not always occur during early boot. In devices that keep a second firmware image and switch to it only after verifying it, the new image is verified while the current firmware runs, so verification competes with the device's normal workload for CPU, RAM, and energy. The optimizations in {{sig-mem}} and {{sig-perf}} are therefore especially relevant when verification runs concurrently with normal operation.

### Suggestions for benchmarking ML-DSA Signing Performance

When benchmarking ML-DSA signing performance in constrained cryptographic modules, it is
important to account for the probabilistic nature of the rejection-sampling loop. Reporting
only a single timing measurement or a best-case execution time may lead to misleading conclusions
about practical performance.

Libraries implementing ML-DSA should provide a mechanism to report the number of
rejection-sampling iterations used during the most recent signing operation. This enables
benchmarking tools to accurately compute average signing times across multiple signing operations.

To provide a more comprehensive assessment of ML-DSA signing performance, benchmarks may report
all or some of the following metrics:

1. Single-iteration signing time:
The signing time for a signature operation that completes within a single iteration of the
rejection-sampling loop. This metric includes the fixed setup cost incurred once per signing
call (such as matrix expansion, message digest computation, and similar precomputations), plus
the cost of one loop operation. It reflects the best-case performance of the signing algorithm
and provides insight into the efficiency of the core signing operation.

2. Average signing time:
Since the iteration count follows a geometric distribution (as described in {{mldsa-rej-sampling}}),
the expected signing time can be computed analytically as the fixed setup cost plus the per-iteration
cost multiplied by the expected number of iterations from {{Expected_Attempts}}.
Implementations may instead measure average signing time empirically over a sufficiently large number of
signing operations, using independent messages and, where applicable, independent randomness, to validate
against the analytical model on the target hardware. This approach requires identifying a message, key,
and randomness combination that results in the expected iteration count.

Rather than relying on ad hoc random inputs, benchmarks may use a standardized input data set covering best-case,
average, and worst-case vectors with documented occurrence probabilities, to ensure reproducibility and
comparability across implementations.

# Additional Considerations for PQC Use in Constrained Devices

## Key Rotation and Renewal

In constrained devices, managing the lifecycle of cryptographic
keys including periodic key rotation and renewal is critical for maintaining long-term
security and supporting cryptographic agility. While constrained devices may rely on
dedicated key-storage hardware for secure key storage and operations, the
responsibility for orchestrating key rotation typically resides in the application layer
or external device management infrastructure.

Although the underlying cryptographic module may offer primitives to securely generate new
key pairs, store fresh seeds, or delete obsolete keys, these capabilities must be
integrated into the device's broader key management framework. This process is especially
important in the context of PQC, where evolving research may lead to changes in
recommended algorithms, parameters, and key management practices.

The security of PQC schemes continues to evolve, with potential risks arising from
advances in post-quantum algorithms, cryptanalytic or implementation vulnerabilities. As a
result, constrained devices should be designed to support flexible and updatable key
management policies. This includes the ability to:

- Rotate keys periodically to provide forward-secrecy,

- Update algorithm choices or key sizes based on emerging security guidance,

- Reconfigure cryptographic profile of the device via firmware updates.

# Post-quantum Firmware Upgrades for Constrained Devices

Constrained devices deployed in the field require periodic firmware upgrades to patch
security vulnerabilities, introduce new cryptographic algorithms, and improve overall
functionality. However, if not designed to withstand attacks from a Cryptographically
Relevant Quantum Computer (CRQC), the firmware update process itself can become a critical
attack vector. If an adversary compromises the update mechanism, they could introduce malicious
firmware, undermining all other security properties of the cryptographic modules. Therefore,
ensuring a post-quantum firmware upgrade process is critical for the security of deployed constrained
devices.

CRQCs pose an additional risk by breaking traditional digital signatures (e.g., RSA,
ECDSA) used to authenticate firmware updates. If firmware verification relies on
traditional signature algorithms, attackers could generate forged signatures in the future
and distribute malicious updates.

## Post-Quantum Firmware Authentication

To ensure the integrity and authenticity of firmware updates, constrained devices will have to adopt PQC digital signature schemes for code signing.
These algorithms must provide long-term security, operate efficiently in low-resource environments, and be compatible with secure update mechanisms, such as the firmware update architecture for IoT described in {{!RFC9019}}.

{{?I-D.ietf-suit-mti}} defines mandatory-to-implement cryptographic algorithms for IoT devices, and recommends use of HSS/LMS {{?RFC8554}} to secure software devices. The SUIT working group may consider adding post-quantum algorithms, such as SLH-DSA and ML-DSA, in future specifications.

Stateful hash-based signature schemes, such as HSS/LMS or the similar XMSS {{?RFC8391}}, are good candidates for signing firmware updates. Those schemes offer efficient verification times, making them more practical choices for constrained environments where performance and memory usage are key concerns.
Their security is based on the security of the underlying hash function, which is well-understood.
A major downside of stateful hash-based signatures is the requirement to keep track of which One-Time Signature (OTS) keys have been used, since reuse of a single OTS key allows for signature forgeries.
However, in the case of firmware updates, the OTS keys will be signing versioned updates, which may make state management easier.
{{?I-D.ietf-pquip-hbs-state}} discusses various strategies for a correct state and backup management for stateful hash-based signatures.

Other post-quantum signature algorithms may also be viable for firmware signing:

- SLH-DSA, a stateless hash-based signature specified in {{FIPS205}}, also has well-understood security based on the security of its underlying hash function, and additionally doesn't have the complexities associated with state management that HSS and XMSS have.

However, signature generation and verification are comparatively slow, and signature sizes are generally larger than other post-quantum algorithms.
SLH-DSA's suitability as a firmware signing algorithm will depend on the capabilities of the underlying hardware.

- ML-DSA is a lattice-based signature algorithm specified in {{FIPS204}}.
It is more performant than SLH-DSA, with significantly faster signing and verification times, as well as shorter signatures.

This will make it possible to implement on a wider range of constrained devices.
The mathematical problem underpinning ML-DSA, Module Learning With Errors (M-LWE), is believed to be a hard problem by the cryptographic community, and hence ML-DSA is believed to be secure.
Cryptographers are more confident still in the security of hash-based signatures than M-LWE, so developers may wish to factor that in when choosing a firmware signing algorithm.

## Hybrid Signature Approaches

To enable secure migration from traditional to post-quantum security, PQ/T hybrid digital signature methods can be used for firmware authentication, combining a traditional and a post-quantum algorithm using either non-composite or composite constructions as defined in {{?RFC9794}}.

A non-composite approach, where both signatures are generated and carried separately, is simple to implement, requires minimal changes to existing signing, and aligns well with current secure boot and update architectures.

Composite constructions, which combine multiple algorithms into a single signature, require changes to cryptographic processing. In such constructions, the additional cost of including a traditional algorithm is typically small compared to the post-quantum component, and overall resource usage remains dominated by the post-quantum algorithm, particularly in terms of key size, signature size, code size, and verification cost.

Implementations should ensure that verification enforces the intended hybrid authentication property, namely that authentication remains secure as long as at least one component algorithm remains secure.

# IANA Considerations

This document requires no IANA actions.

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

ML-DSA supports both deterministic and hedged signing. On platforms where side-channel attacks are a concern and cannot be otherwise mitigated, hedged signing should be used, as discussed in Section 3.4 of {{FIPS204}}.

# Acknowledgments

Thanks to Jean-Pierre Fiset, Richard Kettlewell, Mike Ounsworth, Russ Housley, Keegan Dasilva Barbosa, Hannes Tschofenig and Aritra Banerjee for the detailed review.
