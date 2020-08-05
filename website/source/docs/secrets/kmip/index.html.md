---
layout: "docs"
page_title: "KMIP - Secrets Engines"
sidebar_title: "KMIP <sup>ENTERPRISE</sup>"
sidebar_current: "docs-secrets-kmip"
description: |-
  The KMIP secrets engine allows Vault to act as a KMIP server provider and
  handle the lifecycle of it KMIP managed objects.
---

# KMIP Secrets Engine

The KMIP secrets engine allows Vault to act as a KMIP server provider and handle
the lifecycle of it KMIP managed objects. KMIP, which stands for [Key Management
Interoperability Protocol](#kmip-spec), is a standardized protocol that allows
services and applications to perform cryptographic operations without having to
manage cryptographic material, otherwise known as manage objects, by delegating
its storage and lifecycle to a key management server.

## Setup

The KMIP secrets engine must be configured before it can start accepting KMIP
requests. 

1. Enable the KMIP secrets engine

    ```text
    $ vault secrets enable kmip
    Success! Enabled the kmip secrets engine at: kmip/
    ```

1. Configure the secrets engine with the desired listener addresses to use and
TLS parameters, or leave unwritten to use default values

    ```text
    $ vault write kmip/config listen_addrs=0.0.0.0:5696 
    ```

## Usage

### Scopes and Roles

The KMIP secrets engine uses the concept of scopes to partition KMIP managed
object storage into multiple named buckets. Within a scope, roles can be created
which dictates the set of allowed operations that the particular role can perform.
TLS client certificates can be generated for a role, which services and applications
can then use when sending KMIP requests against Vault's KMIP secret engine.

In order to generate client certificates for KMIP clients to interact with Vault's
KMIP server, we must first create a scope and role and specify the desired set of
allowed operations for it.

1. Create a scope:

    ```text
    $ vault write -f kmip/scope/my-service             
    Success! Data written to: kmip/scope/my-service
    ```
    
1. Create a role within the scope, specifying the set of operations to allow or
deny.

    ```text
    $ vault write kmip/scope/my-service/role/admin operation_all=true 
      Success! Data written to: kmip/scope/my-service/role/admin
    ```
    
### Client Certificate Generation

Once a scope and role has been created, client certificates can be generated for
that role. The client certificate then can be provided to applications and
services that supports KMIP to establish communication with Vault's KMIP server.
The certificate contains scope and role identifiers embedded in the certificate,
which will be used when evaluating permissions during a KMIP request.

1. Generate a client certificate. This returns the CA Chain, the certificate,
and the private key.

    ```text
    $ vault write -f kmip/scope/my-service/role/admin/credential/generate
      Key              Value
      ---              -----
      ca_chain         [-----BEGIN CERTIFICATE-----
      MIICNTCCAZigAwIBAgIUKqNFb3Zy+8ypIhTDs/2/8f/xEI8wCgYIKoZIzj0EAwIw
      HTEbMBkGA1UEAxMSdmF1bHQta21pcC1kZWZhdWx0MB4XDTE5MDYyNDE4MjQyN1oX
      DTI5MDYyMTE4MjQ1N1owKjEoMCYGA1UEAxMfdmF1bHQta21pcC1kZWZhdWx0LWlu
      dGVybWVkaWF0ZTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAbniGNXHOiPvSb0I
      fbc1B9QkOmdT2Ecx2WaQPLISplmO0Jm0u0z11CGuf3Igby7unnCNvCuCXrKJFCsQ
      8JGhwknNAG3eesSZxG4tklA6FMZjE9ETUtYfjH7Z4vuJSw/fxOeey7fhrqAzhV3P
      GRkvA9EQUHJOeV4rEpiINP/fneHNfsn1o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYD
      VR0TAQH/BAgwBgEB/wIBCTAdBgNVHQ4EFgQUR0o0v4rPiBU9RwQfEUucx3JwbPAw
      HwYDVR0jBBgwFoAUMhORultSN+ABogxQdkt7KChD0wQwCgYIKoZIzj0EAwIDgYoA
      MIGGAkF1IvkIaXNkVfe+q0V78CnX0XIJuvmPpgjN8AQzqLci8txikd9gF1zt8fFQ
      gIKERm2QPrshSV9srHDB0YnThRKuiQJBNcDjCfYOzqKlBHifT4WT4OX1U6nP/Y2b
      imGaLJK9VIwfcJOpVCFGp7Xi8QGV6rJIFiQAqzqCy69vcU6nVMsvens=
      -----END CERTIFICATE----- -----BEGIN CERTIFICATE-----
      MIICKjCCAYugAwIBAgIUerDfApmkq0VYychkhlxEnBlIDUcwCgYIKoZIzj0EAwIw
      HTEbMBkGA1UEAxMSdmF1bHQta21pcC1kZWZhdWx0MB4XDTE5MDYyNDE4MjQyNloX
      DTI5MDYyMTE4MjQ1NlowHTEbMBkGA1UEAxMSdmF1bHQta21pcC1kZWZhdWx0MIGb
      MBAGByqGSM49AgEGBSuBBAAjA4GGAAQBA466Axrrz+HWanNe35gPVvB7OE7TWZcc
      QZw1QSMQ+QIQMu5NcdfvZfh68exhe1FiJezKB+zeoJWp1Q/kqhyh7fsAFUuIcJDO
      okZYPTmjPh3h5IZLPg5r7Pw1j99rLHhc/EXF9wYVy2UeH/2IqGJ+cncmVgqczlG8
      m36g9OXd6hkofhCjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/
      AgEKMB0GA1UdDgQWBBQyE5G6W1I34AGiDFB2S3soKEPTBDAfBgNVHSMEGDAWgBQy
      E5G6W1I34AGiDFB2S3soKEPTBDAKBggqhkjOPQQDAgOBjAAwgYgCQgGtPVCtgDc1
      0SrTsVpEtUMYQKbOWnTKNHZ9h5jSna8n9aY+70Ai3U57q3FL95iIhZRW79PRpp65
      d6tWqY51o2hHpwJCAK+eE7xpdnqh5H8TqAXKVuSoC0WEsovYCD03c8Ih3jWcZn6N
      kbz2kXPcAk+dE6ncnwhwqNQgsJQGgQzJroH+Zzvb
      -----END CERTIFICATE-----]
      certificate      -----BEGIN CERTIFICATE-----
      MIICOzCCAZygAwIBAgIUN5V7bLAGu8QIUFxlIugg8fBb+eYwCgYIKoZIzj0EAwIw
      KjEoMCYGA1UEAxMfdmF1bHQta21pcC1kZWZhdWx0LWludGVybWVkaWF0ZTAeFw0x
      OTA2MjQxODQ3MTdaFw0xOTA2MjUxODQ3NDdaMCAxDjAMBgNVBAsTBWNqVVNJMQ4w
      DAYDVQQDEwVkdjRZbTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEANVsHV8CHYpW
      CBKbYVEx/sLphk67SdWxbII4Sc9Rj1KymApD4gPmS+rw0FDMZGFbn1sAfpqMBqMj
      ylv72o9izbYSALHnYT+AaE0NFn4eGWZ2G0p56cVmfXm3ZI959E+3gvZK6X5Jnzm4
      FKXTDKGA4pocYec/rnYJ5X8sbAJKHvk1OeO+o2cwZTAOBgNVHQ8BAf8EBAMCA6gw
      EwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFBEIsBo3HiBIg2l2psaQoYkT
      D1RNMB8GA1UdIwQYMBaAFEdKNL+Kz4gVPUcEHxFLnMdycGzwMAoGCCqGSM49BAMC
      A4GMADCBiAJCAc8DV23DJsHV4fdmbmssu0eDIgNH+PrRKdYgqiHptbuVjF2qbILp
      Z34dJRVN+R9B+RprZXkYiv7gJ/47KSUKzRZpAkIByMjZqLtcypamJM/t+/O1BSst
      CWcblb45FIxAmO4hE00Q5wnwXNxNnDHXWiuGdSNmIBjpb9nM5wehQlbkx7HzvPk=
      -----END CERTIFICATE-----
      private_key      -----BEGIN EC PRIVATE KEY-----
      MIHcAgEBBEIB9Nn7M28VUVW6g5IlOTS3bHIZYM/zqVy+PvYQxn2lFbg1YrQzfd7h
      sdtCjet0lc7pvtoOwd1dFiATOGg98OVN7MegBwYFK4EEACOhgYkDgYYABADVbB1f
      Ah2KVggSm2FRMf7C6YZOu0nVsWyCOEnPUY9SspgKQ+ID5kvq8NBQzGRhW59bAH6a
      jAajI8pb+9qPYs22EgCx52E/gGhNDRZ+HhlmdhtKeenFZn15t2SPefRPt4L2Sul+
      SZ85uBSl0wyhgOKaHGHnP652CeV/LGwCSh75NTnjvg==
      -----END EC PRIVATE KEY-----
      serial_number    317328055225536560033788492808123425026102524390
    ```

### Supported KMIP Operations

The KMIP protocol supports a wide [variety of operations](#kmip-ops) that can be
issued by clients to perform certain actions, such as key management,
encryption, signing, etc. The KMIP secrets engine currently supports a subset of
KMIP operations.

Supported KMIP operations:

```text
operation_create
operation_rekey
operation_locate
operation_get
operation_activate
operation_revoke
operation_destroy
operation_discover_versions
```

Additionally, there are two pseudo-operations that can be used to allow or deny
all operation capabilities to a role. These operations are mutually exclusive to
all other operations. That is, if it's provided during role creation or update,
no other operations can be provided. Similarly, if an existing role contains a
pseudo-operation, and it is then updated with a set supported operation, it will
be overwritten with the newly set of provided operations.

Pseudo-operations:

```text
operation_all
operation_none
```

[kmip-spec]: http://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html
[kmip-ops]: http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html#_Toc490660840