---
version: 1.0.0
status: Draft
date: 2023-09-21
---
# IDealWALLET | Specification: KASMIR DID Method Specification


Tobias Ehrlich (KAPRION Technologies GmbH)  
[tobias.ehrlich@kaprion.de](mailto:tobias.ehrlich@kaprion.de)  
Petr Apletauer (KAPRION Technologies GmbH)  
[petr.apeltauer@kaprion.de](mailto:petr.apeltauer@kaprion.de)  
Ben Biedermann (formerly KAPRION Technologies GmbH)  
[bb@dvctvs.wtf](mailto:bb@dvctvs.wtf)  
version 1.0.0, 2023-09-21  
Draft

## Table of Contents

*   [Abstract](#_abstract)
*   [1\. Conformance](#_conformance)
*   [2\. Terminology](#_terminology)
*   [3\. Introduction](#_introduction)
*   [4\. Concept](#_concept)
    *   [4.1. Keys](#_keys)
    *   [4.2. Events](#_events)
    *   [4.3. Key Event Log](#_key_event_log)
    *   [4.4. Key Event Receipt Log](#_key_event_receipt_log)
    *   [4.5. Key State](#_key_state)
    *   [4.6. Resolver Metadata](#_resolver_metadata)
    *   [4.7. The DID Document](#_the_did_document)
*   [5\. DID Specification](#_did_specification)
    *   [5.1. Method Name](#_method_name)
    *   [5.2. Method Specific Identifier](#_method_specific_identifier)
*   [6\. Protocols](#_protocols)
    *   [6.1. Create](#_create)
    *   [6.2. Read](#_read)
    *   [6.3. Rotate](#_rotate)
    *   [6.4. Delete](#_delete)
    *   [6.5. Deactivate](#_deactivate)
    *   [6.6. Resolving (offline)](#_resolving_offline)
*   [7\. Security Considerations](#_security_considerations)
    *   [7.1. Key State Verification](#_key_state_verification)
    *   [7.2. Confidentiality Violations, Password Sniffing](#_confidentiality_violations_password_sniffing)
    *   [7.3. Replay Attacks](#_replay_attacks)
    *   [7.4. Message Insertion, Deletion, Modification](#_message_insertion_deletion_modification)
    *   [7.5. Man-In-The-Middle Attacks](#_man_in_the_middle_attacks)
*   [References](#_references)

[](#_abstract)[Abstract](#_abstract)
------------------------------------

Most Decentralized Identifier (DIDs) target Distributed Ledgers Technologies (DLT) or require to be online to achieve a sufficient level of trust. This document serves the specification for the generation and interpretation of an offline capable DID method branded KASMIR DID.

[](#_conformance)[1\. Conformance](#_conformance)
-------------------------------------------------

In this document the key words _MAY_, _MUST_, _MUST NOT_, and _SHOULD_ are used and to be interpreted as described in [\[RFC2119\]](#RFC2119) and when they appear, they are capitalized.

[](#_terminology)[2\. Terminology](#_terminology)
-------------------------------------------------

### ASM

Hardware Secure Module with installed Secure Applet

### DID

Decentralized Identifier [\[DID-CORE\]](#DID-CORE)

### DLT

Distributed Ledgers Technologies

### EC

Elliptic Curves

### Holder

the subject who holds one or more credentials and generating presentations from them

### HSM

Hardware Secure Module

### ID

identifier is a name that identifies/labels a unique class of objects

### Issuer

creating and issuing a credential

### IRI

Internationalized Resource Identifiers

### JSON

JavaScript Object Notation

### JWK

JSON Web Key as specified in [\[RFC7517\]](#RFC7517)

### KAPRION

Cooperative and Adaptive Process Interoperability Online Network (Kooperatives und Adaptives Prozess-Interoperabilitäts-Online-Netzwerk)

### KASMIR

KAPRION ASM Mír

### SSI

Self-Sovereign Identity, a paradigm of digital identity control that returns control of an entity’s own digital being to that entity itself.

### URI

Uniform Resource Identifier

### URN

Uniform Resource Name

### UUID

Universally Unique Identifier

### Verifier

is receiving one or more credentials, optionally inside a presentation, for processing

### W3C

World Wide Web Consortium

### Witness

is an entity which validates or anchors the key event log with key states.

[](#_introduction)[3\. Introduction](#_introduction)
----------------------------------------------------

In den meisten Fällen kann keine flächendeckende Garantie ausgesprochen werden, dass Geräte, die digitale Kommunikationsfähigkeiten besitzen, immer an einem aktiven Netzwerk hängen und somit nicht immer online auf Daten zugreifen können. Für die meisten web-basierende Angebote stellt das kein Problem dar, da sie ohnehin nur online verfügbar sind, dennoch sollten Daten ebenso leicht ohne Drittnetze (im folgendem als offline bezeichnet) austauschbar sein, ähnlich wie seit Jahrhunderten Zahlungsmittel ihren Besitzer wechseln. Eine offline fähige ID muss jedoch auch auch vertrauenswürdig sein, denn schließlich hat ein Gerät nicht immer die gleichen interfaces wie ein etwaiger menschlicher Konterfei, um zusätzliche attribute zu prüfen. Diese Anforderungen gelingen nur in zusammenspiel verschiedener Komponenten. Im folgendem wird die did:kasmir vorgestellt, verschiedene Technologien vereint, bzw. erweitert.

Zur Offlinefähigkeit wird als Anforderung eine ledger agnostic voraus gesetzt, die u.a. von [\[DID-KEY\]](#DID-KEY), wo der identifier den public key darstellt, [\[DID-WEB\]](#DID-WEB) [\[DID-PEER\]](#DID-PEER) [\[DID-KERI\]](#DID-KERI)

*   Anforderungen HSM, offline, ohne DLT, Interop
    
*   basiert auf einer modifizierten KERI
    
*   merge peer / web
    

The DID method _MUST_ be ledger agnostic

*   **did:peer** Method 2 allows us to resolve the DID offline ⇒ we should have something similar for **did:keri** if possible
    
*   if DID cannot be resolved, DID resolver should look into the DIDComm message attachments to take DID Document from there
    
*   if the DID Document cannot be resolved and is not in attachments → send **_adopted_ problem-report message**
    
*   Resolution by KERI docs:
    
    *   [KERI DID Mehthod](https://identity.foundation/keri/did\_methods/#read)
        
    

The KASMIR DID specification conforms the requirements of the Decentralized Identifiers v1.0 Specification [\[DID-CORE\]](#DID-CORE) and will be prefixed with `did:kasmir`.

[](#_concept)[4\. Concept](#_concept)
-------------------------------------

### [](#_keys)[4.1. Keys](#_keys)

*   seems we need only **Assertion** and **Key Agreement** key pairs ([see](https://www.w3.org/TR/did-core/#verification-relationships))
    
*   well perhaps also **Authentication** key pair to authenticate 2 HW chips…​
    
*   **symmetric session key** will be created from the **Key Agreement** key pair
    

### [](#_events)[4.2. Events](#_events)

### [](#_key_event_log)[4.3. Key Event Log](#_key_event_log)

tbd.

### [](#_key_event_receipt_log)[4.4. Key Event Receipt Log](#_key_event_receipt_log)

tbd.

### [](#_key_state)[4.5. Key State](#_key_state)

tbd.

The [did:peer section for Method 2](https://identity.foundation/peer-did-method-spec/#generation-method) describes how all keys can be compressed as one long identifier. In KERI it is not forbidden to generate something similar but other information also need to be added. Also there is a big disadvantage because it is not realy efficient to handle such long identifier in the Applet. Therefore I (@Tobias) recommend to generate a URL like string as it is described in the [W3C Decentralized Identifiers (DIDs) v1.0]([https://www.w3.org/TR/did-core/#did-url-syntax) specification. As described above the _key state_ object is part of the DID document so it might be useful to attach it as part of a base64url encrypted DID fragment.

```did:keri:prefix#base64KeyStateObject```

Alternatively a query could be constructed:

```did:keri:prefix?keyState=base64KeyStateObject```

If we assume the ICP event above is the last key state event, then we can create

    did:keri:EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM#ImtleVN0YXRlIjp7InYiOiJLRVJJMTBKU09OMDAwMTFjXyIsImkiOiJFWkFvVE5aSDNVTHZhVTZaLWkwZDhKSlIybm13eVlBZlNWUHpoelM2YjVDTSIsInMiOiIwIiwidCI6ImljcCIsImt0IjoiMSIsImsiOlsiRGFVNkpSMm5td3laLWkwZDhKWkFvVE5aSDNVTHZZQWZTVlB6aHpTNmI1Q00iXSwibiI6IkVaLWkwZDhKWkFvVE5aSDNVTHZhVTZKUjJubXd5WUFmU1ZQemh6UzZiNUNNIiwid3QiOiIxIiwidyI6WyJEVE5aSDNVTHZhVTZKUjJubXd5WUFmU1ZQemh6UzZiWi1pMGQ4SlpBbzVDTSJdLCJjIjpbIkVPIl19

or

    did:keri:EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM?keyState=eyJ2IjoiS0VSSTEwSlNPTjAwMDExY18iLCJpIjoiRVpBb1ROWkgzVUx2YVU2Wi1pMGQ4SkpSMm5td3lZQWZTVlB6aHpTNmI1Q00iLCJzIjoiMCIsInQiOiJpY3AiLCJrdCI6IjEiLCJrIjpbIkRhVTZKUjJubXd5Wi1pMGQ4SlpBb1ROWkgzVUx2WUFmU1ZQemh6UzZiNUNNIl0sIm4iOiJFWi1pMGQ4SlpBb1ROWkgzVUx2YVU2SlIybm13eVlBZlNWUHpoelM2YjVDTSIsInd0IjoiMSIsInciOlsiRFROWkgzVUx2YVU2SlIybm13eVlBZlNWUHpoelM2YlotaTBkOEpaQW81Q00iXSwiYyI6WyJFTyJdfQ

Note: The JSON was minified before base64url encoding

A simple key state event from [\[KERI\]](#KERI) whitepaper

    {
        "v" : "KERI10JSON00011c_",
        "i" : "EZAoTNZH3ULvaU6Z-i0d8JJR2nmwyYAfSVPzhzS6b5CM", //DID of owner = controller
        "s" : "0",
        "t" :  "icp",
        "kt":  "1",
        "k" :  [
                 "CF5pxRJP6THrUtlDdhh07hJEDKrJxkcR9m5u1xs33bhp",    //C ~ X25519KeyAgreementKey2019
                 "DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM",    //D ~ Ed25519VerificationKey2018 or Ed25519VerificationKey2020 (just choose one)
                 "1AABAsL0-AEWBfl876zt4XcTWpGcA4V248OF-n-8gou45OZA" //1AAB ~ EcdsaSecp256k1VerificationKey2019
               ],
        "n" :  "EZ-i0d8JZAoTNZH3ULvaU6JR2nmwyYAfSVPzhzS6b5CM",
        "wt":  "1",
        "w" : ["DTNZH3ULvaU6JR2nmwyYAfSVPzhzS6bZ-i0d8JZAo5CM"],
        "c" :  ["EO"]
    }

### [](#_resolver_metadata)[4.6. Resolver Metadata](#_resolver_metadata)

tbd.

Like did:peer KERI keys also can have a _purposecode_ and _transform_ information but it is not encoded in constant two bytes, depending on purpose and/or key type the code length can go up to 12 bytes. At the moment only a length up to 4 bytes is documented.

### [](#_the_did_document)[4.7. The DID Document](#_the_did_document)

tbd.

*   DID Doc used in DIDComm
    
*   Key State compact but needs to be resolved to DID Doc
    
*   Key Log a set of Key states
    

see issue 20 IDeal wallet

A simple DID document taken from example 1 of [\[DID-CORE\]](#DID-CORE)

    {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ]
      "id": "did:example:123456789abcdefghi",
      "authentication": [{
        "id": "did:example:123456789abcdefghi#keys-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123456789abcdefghi",
        "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
      }]
    }

[](#_did_specification)[5\. DID Specification](#_did_specification)
-------------------------------------------------------------------

### [](#_method_name)[5.1. Method Name](#_method_name)

The method name that identifies this DID method _MUST_ be: `kasmir`.

When `did:kasmir` is used a ASM which fulfills KAPRIONs KASMIR Applet specification _MUST_ be used, an additional registry, such as DLT, _MAY_ be optionally. If connected to an additional register the KASMIR method name _MUST_ be pressent to identify the additional capabilities of the KASMIR applet.

Possible DID strings:

*   `did:kasmir:method-specific-id`
    
*   `did:peer:3method-specific-id`; Note the numalgo _3_ is not yet defined Peer DID Method.
    
*   `did:indy:kasmir:method-specific-id`
    
*   `did:indy:sov:kasmir:method-specific-id`
    
*   `did:…:kasmir:method-specific-id`
    

### [](#_method_specific_identifier)[5.2. Method Specific Identifier](#_method_specific_identifier)

Like in KERI the method specific identifier for the `kasmir` method is a self-addressing identifier which is fully generated and maintained within the ASM and protected by hardware.

The KASMIR self-addressing identifier is cryptographically bound to the inception keys used to create it.

[](#_protocols)[6\. Protocols](#_protocols)
-------------------------------------------

### [](#_create)[6.1. Create](#_create)

wip.

1.  Required Applet calls
    
    1.  init Key Object
        
    2.  add n key(s)
        
    3.  add m witness(es)/anchors
        
    4.  gen method-specific-id
        
    
2.  Generate Key State
    
    1.  add public keys
        
    2.  add info about next keys
        
    3.  add witness(es) and anchors (otional)
        
    4.  sign the ICP
        
    5.  store the ICP in a key event log (KEL)
        
    
3.  generate DID document (App)
    
    1.  convert key event message to JSON
        
    2.  extract prefix and gen did-string
        
    3.  extract keys and add them to verificationMethod object
        
    4.  add additional info
        
    5.  add JSON key event message to DID document
        
    

#### [](#_prefix_generation)[6.1.1. Prefix generation](#_prefix_generation)

Symbols

*   𝑁NN … prefix derivation code letter
    
*   𝐻HH … SHA-256
    
*   𝐷DD … Base64URL derivation
    
*   𝑄QQ … current Public Key
    
*   𝑄′Q′Q' … next Public Key
    
*   𝑄̂Q^\\hat{Q} … witness Public Key
    
*   𝑝𝑎𝑏pabpab … prefix agreement byte
    

Generation process

1.  generate the full KERI object (add keys & witness & prefix agreement byte aka configuration mode)
    
2.  generate a SHA-256 hash over all pre-rotaded public keys
    
    𝑛𝑒𝑥𝑡\=𝐻(𝑄′0,⋯,𝑄′𝑛),𝑛∈ℕnext\=H(Q0′,⋯,Qn′),n∈N
    
    next = H(Q'\_0, \\cdots, Q'\_n), n \\in \\mathbb{N}
    
3.  generate a SHA-256 hash over all current public keys
    
    𝑐𝑢𝑟𝑟𝑒𝑛𝑡\=𝐻(𝑄0,⋯,𝑄𝑛),𝑛∈ℕcurrent\=H(Q0,⋯,Qn),n∈N
    
    current = H(Q\_0, \\cdots, Q\_n), n \\in \\mathbb{N}
    
4.  generate a SHA-256 hash over all witnesses
    
    𝑤𝑖𝑡𝑛𝑒𝑠𝑠𝑒𝑠\=𝐻(𝑄̂0,⋯,𝑄̂𝑚),𝑚∈ℕwitnesses\=H(Q^0,⋯,Q^m),m∈N
    
    witnesses = H(\\hat{Q}\_0, \\cdots, \\hat{Q}\_m), m \\in \\mathbb{N}
    
    This step can provide a hen-egg-problem if the witnesses isn’t already established and the event is not a delegated inception event (DIP), therefore this is at the moment a not available for public.
    
5.  concatenate prefix agreement byte, current, next and witnesses and generate a SHA-256 hash
    
    𝑑𝑎𝑡𝑎\=𝐻(𝑝𝑎𝑏‖𝑐𝑢𝑟𝑟𝑒𝑛𝑡‖𝑛𝑒𝑥𝑡 \[‖𝑤𝑖𝑡𝑛𝑒𝑠𝑠𝑒𝑠\])data\=H(pab‖current‖next \[‖witnesses\])
    
    data = H(pab \\mathbin\\Vert current \\mathbin\\Vert next~\[\\mathbin\\Vert witnesses\])
    
6.  generate a Base64URL string of the resulting hash
    
    𝑑𝑖𝑔𝑒𝑠𝑡\=𝐷(𝑑𝑎𝑡𝑎)digest\=D(data)
    
    digest = D(data)
    
7.  add derivation code for KAPRION Version
    
    𝑚𝑒𝑡ℎ𝑜𝑑−𝑠𝑝𝑒𝑐𝑖𝑓𝑖𝑐−𝑖𝑑\='N'‖𝑑𝑖𝑔𝑒𝑠𝑡method−specific−id\='N'‖digest
    
    method-specific-id = \\text{'N'} \\mathbin\\Vert digest
    

### [](#_read)[6.2. Read](#_read)

tbd.

    sequenceDiagram
        Alice->>John: Hello John, how are you?
        John-->>Alice: Great!
        Alice-)John: See you later!

### [](#_rotate)[6.3. Rotate](#_rotate)

tbd.

### [](#_delete)[6.4. Delete](#_delete)

tbd.

### [](#_deactivate)[6.5. Deactivate](#_deactivate)

tbd.

### [](#_resolving_offline)[6.6. Resolving (offline)](#_resolving_offline)

tbd

**How to resolve KERI DID into DID document (meaning JSON object `didDocument` as per [DIDComm v2 docs](https://w3c-ccg.github.io/universal-wallet-interop-spec/#example-3-a-did-resolution-response))** - not just KERI DID is needed for this, but also KEL (Key Event Log) or its current [Key State object](https://identity.foundation/keri/did\_methods/#keyState)

1.  get KEL (Key Event Log) from `keyState` query parameter and service (if available) from `service` parameter
    
    *   `did:keri:prefix?keyState=base64KeyStateObject&didDocService=base64ServiceObject`
        
    *   `service` block is base64 encoded after whitespace removal and common word substitution as in [Peer DID docs](https://identity.foundation/peer-did-method-spec/#multi-key-creation)
        
    
2.  extract prefix string from KEL (attribute `i`) and generate did as did:keri:prefix
    
3.  extract keys (attr. `k`) from KEL (ICP or last ROT event) _\- those are actually only x-coordinates of the pub. key_
    
4.  build DID document -for each key:
    
5.  convert x-coordinate to Base64URL format by removing [derivation code](https://github.com/decentralized-identity/keri/blob/master/kids/kid0001.md#derivation-codes) (e.g. `D`) and adding `=`
    
    *   e.g. `DaU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM` ⇒ `aU6JR2nmwyZ-i0d8JZAoTNZH3ULvYAfSVPzhzS6b5CM=`
        
    
6.  Use [proper crypto algorithm](https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc#public-key-compression-in-the-elliptic-key-cryptosystems) to create full pub. key from the x-coordinate
    
7.  encode the pub.key in Base52 format
    
8.  Get a key `type` by the [derivation code](https://github.com/decentralized-identity/keri/blob/master/kids/kid0001.md#derivation-codes) (1st. char or first 4 chars)
    
    *   `C` is for X25519 public encryption key ⇒ might be [X25519KeyAgreementKey2019](https://ns.did.ai/suites/x25519-2019) or [X25519KeyAgreementKey2020](https://ns.did.ai/suites/x25519-2020/) _\- we can choose which depending on key representation in the DID document_
        
    *   `D` is for Ed25519 public signing verification key ⇒ [Ed25519VerificationKey2018](https://ns.did.ai/suites/ed25519-2018) or [Ed25519VerificationKey2020](https://ns.did.ai/suites/ed25519-2020) _\- we can choose which depending on key representation in the DID document_
        
    *   `1AAB` is for ECDSA secp256k1 public key ⇒ [EcdsaSecp256k1VerificationKey2019](https://ns.did.ai/suites/secp256k1-2019)
        
    
9.  Get key `controller` from attr. `i` _\- we assume the controller is the DID owner_
    
10.  Get key rights ([verification relationship](https://www.w3.org/TR/did-core/#verification-relationships) - `authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`…​)
    
    *   keyAgreement is for key with derivation code `C`
        
    *   all other is for key with derivation code `1AAB` (or `D`)
        
    
11.  add last Key State (ICP or ROT) as DID Document Metadata as defined in [2.5 Resolver Metadata](https://identity.foundation/keri/did\_methods/#resolvermetadata)
    

[](#_security_considerations)[7\. Security Considerations](#_security_considerations)
-------------------------------------------------------------------------------------

This section is non-normative.

### [](#_key_state_verification)[7.1. Key State Verification](#_key_state_verification)

tbd.

### [](#_confidentiality_violations_password_sniffing)[7.2. Confidentiality Violations, Password Sniffing](#_confidentiality_violations_password_sniffing)

tbd.

### [](#_replay_attacks)[7.3. Replay Attacks](#_replay_attacks)

tbd.

### [](#_message_insertion_deletion_modification)[7.4. Message Insertion, Deletion, Modification](#_message_insertion_deletion_modification)

tbd.

### [](#_man_in_the_middle_attacks)[7.5. Man-In-The-Middle Attacks](#_man_in_the_middle_attacks)

tbd.

[](#_references)[References](#_references)
------------------------------------------

*   \[DID-CORE\] Decentralized Identifiers (DIDs) v1.0. M. Sporny; A. Guy; M. Sabadello; D. Reed. W3C. 19. July 2022. W3C Recommendation. URL: [https://www.w3.org/TR/did-core/](https://www.w3.org/TR/did-core/)
    
*   \[DID-KERI\] The did:keri Method v0.1. S. Smith; C. Cunningham; P. Feairheller. Identity Foundation. 10. November 2021. Unofficial Draft. URL: [https://identity.foundation/keri/did\_methods/#security-considerations](https://identity.foundation/keri/did_methods/#security-considerations)
    
*   \[DID-KEY\] The did:key Method v0.7. M. Sporny et al. W3C. September 2022. URL: [https://w3c-ccg.github.io/did-method-key/](https://w3c-ccg.github.io/did-method-key/)
    
*   \[DID-PEER\] Peer DID Method Specification. Oskar Deventer et al. Identity Foundation. 28. June 2023. W3C Document. URL: [https://identity.foundation/peer-did-method-spec/](https://identity.foundation/peer-did-method-spec/)
    
*   \[DID-WEB\] did:web Method Specification. Christian Gribneau et al. W3C. 6. May 2023. URL: [https://w3c-ccg.github.io/did-method-web/](https://w3c-ccg.github.io/did-method-web/)
    
*   \[KERI\] Key Event Receipt Infrastructure (KERI) Design. S. Smith. GitHub. 7. May 2021. v2.60. URL: [https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI\_WP\_2.x.web.pdf](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf)
    
*   \[RFC2119\] Key words for use in RFCs to Indicate Requirement Levels. S. Bradner. IETF. March 1997. URL: [https://www.rfc-editor.org/rfc/rfc2119](https://www.rfc-editor.org/rfc/rfc2119)
    
*   \[RFC7517\] JSON Web Key (JWK). M. Jones. IETF. May 2015. URL: [https://tools.ietf.org/html/rfc7517](https://tools.ietf.org/html/rfc7517)
    

Version 1.0.0  
Last updated 2023-09-21 12:28:55 +0200
