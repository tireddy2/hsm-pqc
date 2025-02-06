---
title: "Adapting HSMs for Post-Quantum Cryptography"
abbrev: "Adapting HSMs for PQC"
category: info

docname: draft-ietf-pquip-pqc-hsm-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "PQUIP"
keyword:
 - PQC
 - HSM


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
    email: "kondtir@gmail.com"

normative:

informative:

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
  REC-KEM:
    title: Recommendations for Key-Encapsulation Mechanisms
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.ipd.pdf 

--- abstract

Hardware Security Modules (HSMs) are integral to securely managing cryptographic keys, especially when deploying Post-Quantum Cryptography (PQC) algorithms, which often require handling significantly larger private keys compared to traditional algorithms. This draft discusses key management strategies for HSMs in the context of PQC and optimizing performance in hardware implementations of PQC signature algorithms.

--- middle

# Introduction

As cryptographic standards evolve to address the threats posed by quantum computing, the deployment of Post-Quantum Cryptography (PQC) algorithms in secure systems has become a pressing challenge. Hardware Security Modules (HSMs) are widely used to securely generate, store, and manage cryptographic keys, but the transition to PQC algorithms introduces new complexities due to the increased size of private keys. HSMs, typically constrained by storage, processing power, and memory, must adapt to efficiently handle these larger key sizes while ensuring the security of cryptographic operations. This draft explores strategies for optimizing HSM performance and security in the context of PQC.

# Key Management in HSMs for PQC

HSMs are designed to securely store and manage cryptographic keys, but their capabilities and constraints must be carefully considered when deploying PQC algorithms. Given the typically larger size of private keys for PQC algorithms, it is important to ensure that HSMs are optimized for handling these larger key sizes without compromising performance or security.

Hardware Security Modules are resource-constrained devices, particularly when dealing with PQC algorithms. The private keys in PQC algorithms (e.g., ML-KEM, ML-DSA or SLH-DSA) can be significantly larger than traditional RSA or ECC keys, placing demands on HSMs’ storage, processing power, and memory. Therefore, HSMs should be configured to prioritize efficient use of available resources while managing these larger keys. One key strategy to mitigate storage limitations is to store only the seed rather than the full expanded private key, as the seed is far smaller and can be used to derive the expanded private key when necessary.

## Seed Management {#Seed}

The seed generated during the PQC key generation function is highly sensitive, as it will be used to compute the private key or decapsulation key. Consequently, seeds must be treated with the same level of security as private keys.

To comply with {{ML-KEM}}, {{ML-DSA}}, {{SLH-DSA}} and {{REC-KEM}} guidelines:

1. **Seed Storage**  
   Seeds must be securely stored within a cryptographic module, such as a Hardware Security Module (HSM), to ensure protection against unauthorized access. Since the seed can be used to compute the private key, it must be safeguarded with the same level of protection as the private key itself. For example, according to {{ML-DSA}} Section 3.6.3, the seed `ξ` generated during `ML-DSA.KeyGen` can be stored for later expansion using `ML-DSA.KeyGen_internal`.

   Vulnerabilities such as the "Unbindable Kemmy Schmidt" attacks {{BIND}} highlight risks where expanded private keys can be manipulated to create exploitable conditions. For instance, an attacker (Mallory) may execute a "re-encapsulation attack" forcing two separate sessions to arrive at the same shared secret key.  
   
   To mitigate such risks, the honest decryptor should re-derive their private key from the seed at decryption time. This ensures consistency and eliminates the potential for manipulation of expanded private keys.  
   
   It is crucial that the **HSM must store only the seed** and not the private key itself, as this approach minimizes risk and ensures compliance with security standards.

   A significant advantage of this approach is that seeds require much less storage than private keys, which is especially important in Hardware Security Modules (HSMs), as they are typically resource-constrained devices. This limitation becomes even more critical with post-quantum cryptography (PQC) algorithms, where private keys can be exceptionally large. By storing only the seed and deriving the private key as needed, HSMs can significantly reduce storage overhead, making this approach highly efficient for scaling operations across multiple key pairs while adhering to the constraints of these devices.

   If the seed is not securely stored at the time of key generation, it is permanently lost because the process of deriving an expanded key from the seed relies on a one-way cryptographic function. This one-way function is designed to ensure that the expanded private key can be deterministically derived from the seed, but the reverse operation, deriving the original seed from the expanded key is computationally infeasible.

   However, this seed-based approach introduces trade-offs in performance, as key derivation incurs additional computation. While HSMs already employ optimized key storage mechanisms, implementations should carefully balance security and efficiency when managing PQC private keys.

2. **Efficient Key Derivation**
   When storing only the seed in an HSM, it is crucial that the HSM is capable of deriving the private key efficiently whenever required. The key derivation process, such as ML-KEM.KeyGen_internal for ML-KEM or similar functions for other PQC algorithms, must be implemented in such a way that it can operate quickly and securely within the resource constraints of the HSM. The derived private key should only be kept in memory temporarily during the cryptographic operation and discarded immediately after use.

3. **Secure Exporting of Seeds**  
   Given the potential for hardware failures or the end-of-life of cryptographic devices, it is essential to plan for backup and recovery of the cryptographic seeds. HSMs should support secure seed backup mechanisms, ideally leveraging encrypted storage and ensuring that the backup data is protected from unauthorized access. In a disaster recovery scenario, the seed should be recoverable to enable the re-derivation of the private key, provided the proper security measures are in place to prevent unauthorized extraction. 
   For secure exporting of seeds, PQC encryption algorithms, such as ML-KEM, should be used to encrypt the seed before export. This ensures that the seed remains protected even if the export process is vulnerable to quantum attacks. The process for secure export should include:
   - Encrypting the seed using a strong, approved PQC encryption algorithm before export.  
   - Ensuring the exported seed is accessible only to authorized entities.  
   - Enforcing strict access controls and secure transport mechanisms to prevent unauthorized access during transfer.

Wherever possible, seed generation, storage, and usage should remain entirely within the cryptographic module. This minimizes the risk of exposure and ensures compliance with established security guidelines.

# Ephemeral Key Management

In protocols like TLS and IPsec, ephemeral keys are used for key exchange. Given the increased size of PQC key material, ephemeral key management will have to be optimized for both security and performance.

For PQC KEMs, ephemeral key-pairs must be generated from an ephemeral seed, which needs to be securely stored temporarily and erased after use. This approach ensures that ephemeral key generation is deterministic and minimizes storage overhead in HSMs, as only the seed (not the full private key) needs to be stored. The ephemeral seed must be securely erased immediately after the key pair is generated to prevent potential leakage or misuse.

Additionally, ephemeral keys should not be reused across different algorithm suites and sessions. Each ephemeral key-pair must be uniquely associated with a specific key exchange instance to prevent cryptographic vulnerabilities, such as cross-protocol attacks or unintended key reuse.

HSMs implementing PQC ephemeral key management will have to:
* Generate ephemeral key-pairs on-demand from an ephemeral seed stored temporarily within the cryptographic module.
* Enforce immediate seed erasure after the key-pair is generated and the cryptographic operation is completed.
* Prevent key reuse across different algorithm suites or sessions.

# Optimizing Performance in Hardware Implementations of PQC Signature Algorithms

When implementing PQC signature algorithms in hardware devices, such as Hardware Security Modules (HSMs), performance optimization becomes a critical consideration. Transmitting the entire message to the HSM for signing can lead to significant overhead, especially for large payloads. To address this, implementers can leverage techniques that reduce the data transmitted to the HSM, thereby improving efficiency and scalability.

One effective approach involves sending only a message digest to the HSM for signing. By signing the digest of the content rather than the entire content, the communication between the application and the HSM is minimized, enabling better performance. This method is applicable for any PQC signature algorithm, whether it is ML-DSA, SLH-DSA, or any future signature scheme. For such algorithms, a mechanism is often provided to pre-hash or process the message in a way that avoids sending the entire raw message for signing. In particular, algorithms like SLH-DSA present challenges due to their construction, which requires multiple passes over the message digest during the signing process. The signer does not retain the entire message or its full digest in memory at once. Instead, different parts of the message digest are processed sequentially during the signing procedure. This differs from traditional algorithms like RSA or ECDSA, which allow for more efficient processing of the message, without requiring multiple passes or intermediate processing of the digest.

To address this challenge, algorithms like ML-DSA offer a form of pre-hash using the mu (message representative) value described in Section 6.2 of {{ML-DSA}}. The mu value provides an abstraction for pre-hashing by allowing the hash or message representative to be computed outside the HSM. This feature offers additional flexibility by enabling the use of different cryptographic modules for the pre-hashing step. The pre-computed mu value is then supplied to the HSM, eliminating the need to transmit the entire message for signing. {{?I-D.ietf-lamps-dilithium-certificates}} discusses leveraging ExternalMu-ML-DSA, where the pre-hashing step (ExternalMu-ML-DSA.Prehash) is performed in a software cryptographic module, and only the pre-hashed message (mu) is sent to the HSM for signing (ExternalMu-ML-DSA.Sign). 
By implementing ExternalMu-ML-DSA.Prehash in software and ExternalMu-ML-DSA.Sign in an HSM, the cryptographic workload is efficiently distributed, making it practical for high-volume signing operations.

# Additional Considerations for HSM Use in PQC

* Key Rotation and Renewal: In an environment where the key material may need to be updated or rotated regularly (such as for compliance or 
  cryptographic agility), the HSM should provide mechanisms to rotate keys securely. This could involve generating new key pairs, securely storing the new seeds, and securely deleting outdated keys.

# Quantum-Safe Firmware Upgrades for HSMs

HSMs deployed in the field require periodic firmware upgrades to patch security vulnerabilities, introduce new cryptographic algorithms, and improve overall functionality. However, the firmware upgrade process itself can become a critical attack vector if not designed to be quantum-safe. If an adversary compromises the update mechanism, they could introduce malicious firmware, undermining all other security properties of the HSM. Therefore, ensuring a quantum-safe firmware upgrade process is critical for the security of deployed HSMs.

CRQCs pose an additional risk by breaking traditional digital signatures (e.g., RSA, ECDSA) used to authenticate firmware updates. If firmware verification relies on traditional signature algorithms, attackers could generate forged signatures in the future and distribute malicious updates.

## Quantum-Safe Firmware Authentication

To ensure the integrity and authenticity of firmware updates, HSM vendors will have to adopt PQC digital signature schemes for code signing. Recommended post-quantum algorithms include:

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm): SLH-DSA does not introduce any new hardness assumptions beyond those inherent to its underlying hash functions. It builds upon established foundations in cryptography, making it a reliable and robust digital signature scheme for a post-quantum world. While attacks on lattice-based schemes like ML-DSA can compromise their security, SLH-DSA will remain unaffected by these attacks due to its distinct mathematical foundations. This ensures the ongoing security of systems and protocols that use SLH-DSA for digital signatures.

HSS-LMS (Hierarchical Signature System - Leighton-Micali Signature): A hash-based signature scheme, providing long-term security and efficient key management for firmware authentication (see {{REC-SHS}}).

Firmware images can be signed using one of these quantum-resistant algorithms before being distributed to HSMs.

# Key Management and Quantum-Safe Authorization
In a post-quantum world, ensuring the secure authorization of PQC private keys stored in HSMs is crucial. This process should involve both explicit and implicit authorization mechanisms:

1. Explicit Authorization: When an actor requests access to a PQC private key, the authorization process should be protected using quantum-safe techniques. This could involve utilizing PQC digital signatures to sign authorization requests, ensuring the integrity of the request against quantum adversaries. The HSM should verify the authorization, ensuring that only trusted parties can access the key.

2. Implicit Authorization (Session Management): Implicit authorization refers to scenarios where access to PQC private key is granted indirectly, typically by establishing a session or opening a secure partition where the keys can be used for specific operations over a defined period. This method helps streamline operations by reducing the need for constant reauthorization, while still ensuring quantum-safe security. For instance, when an actor requires access to a PQC private key, it initiates a session request, which can be authenticated using a PQC digital signature. Once verified, the HSM grants access for the duration of the session, allowing the actor to perform operations without needing further explicit authorization.

# Security Considerations

The security considerations for key management in HSMs for PQC focus on the secure storage and handling of cryptographic seeds, which are used to derive private keys. Seeds must be protected with the same security measures as private keys, and key derivation should be efficient and secure within resource-constrained HSMs. Secure export and backup mechanisms for seeds are essential to ensure recovery in case of hardware failure, but these processes must be encrypted and protected from unauthorized access. 

# Acknowledgements
{:numbered="false"}

TODO
