# Forge.Next.Security

**Certificates made simple. Encryption made accessible.**

[![.NET 8](https://img.shields.io/badge/.NET-8-512BD4?style=flat&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![.NET 9](https://img.shields.io/badge/.NET-9-512BD4?style=flat&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?style=flat&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![.NET 11](https://img.shields.io/badge/.NET-11-512BD4?style=flat&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![C#](https://img.shields.io/badge/Language-C%23-239120?style=flat)](https://learn.microsoft.com/dotnet/csharp/)

[![NuGet version](https://img.shields.io/nuget/v/Forge.Next.Security?style=flat&logo=nuget&logoColor=white)](https://www.nuget.org/packages/Forge.Next.Security)
[![NuGet downloads](https://img.shields.io/nuget/dt/Forge.Next.Security?style=flat&logo=nuget&logoColor=white)](https://www.nuget.org/packages/Forge.Next.Security)
[![License](https://img.shields.io/github/license/JZO001/Forge.Next.Security?style=flat)](https://github.com/JZO001/Forge.Next.Security)
[![GitHub stars](https://img.shields.io/github/stars/JZO001/Forge.Next.Security?style=flat&logo=github)](https://github.com/JZO001/Forge.Next.Security/stargazers)

[![ErrorOr Integration](https://img.shields.io/badge/ErrorOr-Integration-E67E22?style=flat)](https://github.com/amantinband/error-or)
[![Certificates X.509](https://img.shields.io/badge/Certificates-X.509-555555?style=flat)](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates)
[![Encryption AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-555555?style=flat)](https://learn.microsoft.com/dotnet/api/system.security.cryptography.aesgcm)
[![Key derivation PBKDF2](https://img.shields.io/badge/Key_derivation-PBKDF2-555555?style=flat)](https://learn.microsoft.com/dotnet/api/system.security.cryptography.rfc2898derivebytes)

A small, focused, cross-platform .NET security library for **X.509 certificate management** and **authenticated AES-256-GCM encryption** — with first-class support for self-signed certificates (local development, internal services, TLS endpoints) and password-based symmetric encryption using PBKDF2 key derivation.

Every public method returns an [`ErrorOr<T>`](https://github.com/amantinband/error-or) result instead of throwing, so failures are values you handle explicitly rather than exceptions you have to catch.

It is part of the **Forge Patterns and Practices** family.

---

## Table of contents

- [Features](#features)
- [Typical Use Cases](#typical-use-cases)
- [Requirements](#requirements)
- [Installation](#installation)
- [Working with `ErrorOr` results](#working-with-erroror-results)
- [API reference](#api-reference)
  - [`CertificateFactory`](#certificatefactory)
    - [`Localhost` (constant)](#localhost-constant)
    - [`CreateSelfSigned` (without password)](#createselfsigned-without-password)
    - [`CreateSelfSigned` (with password)](#createselfsigned-with-password)
    - [`ExportToPfxRawData`](#exporttopfxrawdata)
    - [`ExportToCerFile`](#exporttocerfile)
    - [`GetForLocalhost`](#getforlocalhost)
    - [`GetFromRawData`](#getfromrawdata)
    - [`GetFromFile`](#getfromfile)
  - [`CertificateAccess`](#certificateaccess)
    - [`AddToStore`](#addtostore)
    - [`FindByThumbprint`](#findbythumbprint)
    - [`GetAllFromStore`](#getallfromstore)
    - [`FindByDnsNames`](#findbydnsnames)
    - [`GetAlternateNames`](#getalternatenames)
    - [`RemoveFromStore`](#removefromstore)
  - [`AesCryptography`](#aescryptography)
    - [`MakeAESKey`](#makeaeskey)
    - [`AesEncrypt`](#aesencrypt)
    - [`AesDecrypt`](#aesdecrypt)
    - [`AesGcmEncrypt`](#aesgcmencrypt)
    - [`AesGcmDecrypt`](#aesgcmdecrypt)
- [How Subject Alternative Names are built](#how-subject-alternative-names-are-built)
- [End-to-end example](#end-to-end-example)
- [Notes, gotchas & platform behaviour](#notes-gotchas--platform-behaviour)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Keywords](#keywords)
- [License](#license)

---

## Features

- 🔐 **Self-signed certificate generation** with sensible, secure defaults (RSA 2048, SHA-256, TLS *Server Authentication* EKU) and a configurable key size.
- 🌐 **Automatic Subject Alternative Names (SAN)** — loopback, "any", `localhost` and the machine name are always included, plus any custom DNS names / IP addresses you supply.
- 💾 **Export & import** to/from PFX (PKCS#12) raw bytes or files, and export the public certificate as a `.cer` (DER) file.
- 🗄️ **Certificate store management** — add, find (by thumbprint or by DNS name), enumerate and remove certificates from the Windows/OS certificate store.
- 🧂 **AES encryption** — PBKDF2 key derivation plus authenticated AES-256-GCM encryption; the legacy AES-CBC `iv:ciphertext` payload stays readable.
- ✅ **Exception-free API** — every method returns `ErrorOr<T>`; nothing throws for expected failures.

All types live in the **`Forge.Next.Security`** namespace.

---

## Typical Use Cases

Forge.Next.Security is particularly useful for:

- Generating self-signed X.509 certificates in C# with custom DNS names and IP addresses (Subject Alternative Names).
- Creating HTTPS certificates for localhost development, including ASP.NET Core and Kestrel.
- Provisioning self-signed TLS certificates for internal services and microservices where certificate trust is explicitly configured.
- Adding, finding, enumerating and removing certificates in the operating system's certificate store, subject to platform support.
- Importing and exporting PFX (PKCS#12) certificates and exporting public certificates as DER (`.cer`) files.
- Encrypting and decrypting sensitive application strings using authenticated AES-256-GCM encryption.
- Deriving cryptographic keys from passwords using PBKDF2.
- Migrating legacy AES-CBC encrypted data to authenticated encryption (see [Security notes](#security-notes)).
- Building security-related workflows with explicit, result-based error handling using `ErrorOr<T>`.

---

## Requirements

| | |
|---|---|
| **Target frameworks** | `net8.0`, `net9.0`, `net10.0`, `net11.0` |
| **Language** | C# 12 |
| **Dependencies** | [`Forge.Next.Shared`](https://github.com/JZO001/Forge.Next.Shared) (brings in `ErrorOr`) |
| **Platforms** | Cross-platform. Certificate-store and friendly-name features are richest on Windows (see [platform notes](#notes-gotchas--platform-behaviour)). |

---

## Installation

```bash
dotnet add package Forge.Next.Security
```

or via the Package Manager Console:

```powershell
Install-Package Forge.Next.Security
```

Then import the namespaces:

```csharp
using Forge.Next.Security;                              // CertificateFactory, CertificateAccess, AesCryptography
using ErrorOr;                                          // ErrorOr<T>, Error, ErrorType
using System.Security.Cryptography.X509Certificates;    // X509Certificate2, StoreName, StoreLocation
```

---

## Working with `ErrorOr` results

Because every method returns `ErrorOr<T>`, you never wrap calls in `try/catch` for expected failures. Inspect the result instead:

```csharp
ErrorOr<X509Certificate2> result = CertificateFactory.GetForLocalhost("CN=localhost", "Dev HTTPS");

if (result.IsError)
{
    // result.FirstError.Type is an ErrorType (Validation, NotFound, Unexpected, …)
    Console.WriteLine($"Failed: {result.FirstError.Type} - {result.FirstError.Description}");
}
else
{
    X509Certificate2 certificate = result.Value;   // safe to read once IsError is false
    Console.WriteLine(certificate.Thumbprint);
}
```

Or use the functional helpers shipped with `ErrorOr`:

```csharp
// Match: project both branches into a single value.
string message = result.Match(
    cert => $"Created {cert.Thumbprint}",
    errors => $"Failed: {errors[0].Description}");

// Then / ThenDo: chain further work that only runs on success.
ErrorOr<byte[]> pfx = CertificateFactory
    .GetForLocalhost("CN=localhost", "Dev HTTPS")
    .Then(cert => CertificateFactory.ExportToPfxRawData(cert, "p@ss"));
```

The error kinds this library produces are:

| `ErrorType` | When |
|-------------|------|
| `Validation` | A required argument was `null` (e.g. a `null` password/salt). The `Description` names the offending parameter. |
| `NotFound` | `CertificateAccess.FindByThumbprint` found no matching certificate. |
| `Unexpected` | An underlying operation threw (wrong PFX password, missing file, …); the exception is caught and converted into this error. |

> In the examples below, code that is not specifically demonstrating error handling reads `.Value` directly for brevity. In production, guard with `IsError` (or `Match`) first.

---

## API reference

| Class | Responsibility |
|-------|----------------|
| [`CertificateFactory`](#certificatefactory) | Create, export and import self-signed certificates. |
| [`CertificateAccess`](#certificateaccess) | Read from and write to the OS certificate store; inspect SAN entries. |
| [`AesCryptography`](#aescryptography) | Derive AES keys (PBKDF2) and encrypt/decrypt strings (authenticated AES-GCM; the legacy AES-CBC format stays readable). |

---

### `CertificateFactory`

> `public static class CertificateFactory`

Creates and manages self-signed certificates. Generated certificates use an **RSA** key (2048-bit by default, configurable), a **SHA-256/PKCS#1** signature, the **TLS Server Authentication** enhanced key usage (`1.3.6.1.5.5.7.3.1`), the `DigitalSignature | KeyEncipherment | DataEncipherment` key usages, and are flagged as **non-CA** (end-entity) certificates.

| Member | Returns | Summary |
|--------|---------|---------|
| `Localhost` | `const string` | The constant `"localhost"`. |
| `CreateSelfSigned(string, string, IEnumerable<string>, DateTime, DateTime, int)` | `ErrorOr<X509Certificate2>` | Create an in-memory self-signed certificate. |
| `CreateSelfSigned(string, string, IEnumerable<string>, DateTime, DateTime, string, int, X509KeyStorageFlags)` | `ErrorOr<X509Certificate2>` | Create a certificate and round-trip it through a password-protected PFX (machine key set). |
| `ExportToPfxRawData(X509Certificate2, string)` | `ErrorOr<byte[]>` | Export the certificate **and** private key as PFX bytes. |
| `ExportToCerFile(X509Certificate2)` | `ErrorOr<byte[]>` | Export the **public** certificate as DER (`.cer`) bytes. |
| `GetForLocalhost(string, string, int)` | `ErrorOr<X509Certificate2>` | Create a long-lived certificate for `localhost`. |
| `GetFromRawData(byte[], string, X509KeyStorageFlags)` | `ErrorOr<X509Certificate2>` | Load a certificate from PFX bytes. |
| `GetFromFile(string, string?, X509KeyStorageFlags)` | `ErrorOr<X509Certificate2>` | Load a certificate from a PFX file. |

---

#### `Localhost` (constant)

```csharp
public const string Localhost = "localhost";
```

The lower-case DNS label `"localhost"`. Useful when you want to reference the same value the factory uses internally.

```csharp
string name = CertificateFactory.Localhost; // "localhost"
```

---

#### `CreateSelfSigned` (without password)

```csharp
public static ErrorOr<X509Certificate2> CreateSelfSigned(
    string x500,
    string friendlyName,
    IEnumerable<string> dnsNames,
    DateTime startTime,
    DateTime endTime,
    int keySize = 2048)
```

Creates a brand-new, **in-memory (ephemeral)** self-signed certificate that owns its freshly generated private key. Nothing is written to disk or to a certificate store.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `x500` | `string` | The X.500 subject distinguished name (e.g. `"CN=My Company"`). `null` is treated as an empty subject. |
| `friendlyName` | `string` | The Windows *friendly name*. Applied only on Windows; ignored on other platforms. |
| `dnsNames` | `IEnumerable<string>` | Additional DNS names and/or IP addresses to add to the SAN. See [how SANs are built](#how-subject-alternative-names-are-built). |
| `startTime` | `DateTime` | Validity start (`NotBefore`). A `DateTime` whose `Kind` is not `Utc` is local time. |
| `endTime` | `DateTime` | Validity end (`NotAfter`), the same way. A local time whose UTC equivalent falls outside `DateTime`'s range (`DateTime.MaxValue` west of UTC, `DateTime.MinValue` east of it) is clamped to the range instead of failing. |
| `keySize` | `int` | RSA key size in bits. Defaults to `2048`. |

**Example**

```csharp
ErrorOr<X509Certificate2> result = CertificateFactory.CreateSelfSigned(
    x500: "CN=My Company, O=My Company Ltd, C=US",
    friendlyName: "My Internal Service",
    dnsNames: new[] { "myapp.local", "api.myapp.local", "192.168.1.50" },
    startTime: DateTime.UtcNow.AddDays(-1),
    endTime: DateTime.UtcNow.AddYears(5),
    keySize: 4096);

if (!result.IsError)
{
    X509Certificate2 certificate = result.Value;
    Console.WriteLine(certificate.Subject);       // CN=My Company, O=My Company Ltd, C=US
    Console.WriteLine(certificate.HasPrivateKey); // True
}
```

> 💡 Use `DateTime.UtcNow` for the validity boundaries so the encoded values are unambiguous across time zones.

---

#### `CreateSelfSigned` (with password)

```csharp
public static ErrorOr<X509Certificate2> CreateSelfSigned(
    string x500,
    string friendlyName,
    IEnumerable<string> dnsNames,
    DateTime startTime,
    DateTime endTime,
    string password,
    int keySize = 2048,
    X509KeyStorageFlags keyStorageFlags =
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet)
```

Same as the overload above, but after creation the certificate is **exported to a password-protected PFX and re-imported**, by default with `X509KeyStorageFlags.Exportable | PersistKeySet | MachineKeySet`. Use this overload when you need the private key persisted in the **machine key store** (for example, a Windows service that must access the key across processes/sessions, or a TLS server on Windows: SChannel fails the handshake with an ephemeral key). The key **stays there** after the certificate is disposed: every call adds one, and nothing in this package removes it (see [Notes](#notes-gotchas--platform-behaviour) for removing one).

**Parameters** — identical to the overload above, plus a `password` (the password protecting the intermediate PFX round-trip), with `keySize` after it, and `keyStorageFlags` last: the flags of the re-import (see [`GetFromRawData`](#getfromrawdata)). Pass `X509KeyStorageFlags.EphemeralKeySet` to keep the key in memory only; macOS has no ephemeral key sets.

**Example**

```csharp
ErrorOr<X509Certificate2> result = CertificateFactory.CreateSelfSigned(
    x500: "CN=My Windows Service",
    friendlyName: "My Service Certificate",
    dnsNames: new[] { "service.internal" },
    startTime: DateTime.UtcNow.AddDays(-1),
    endTime: DateTime.UtcNow.AddYears(2),
    password: "S3cr3t!Passw0rd");

Console.WriteLine(result.IsError ? result.FirstError.Description : result.Value.HasPrivateKey);
```

> ⚠️ **Permissions:** `MachineKeySet` writes to the machine-wide key container. On Windows this typically requires the process to run **elevated (as Administrator)**. If you only need an in-memory key, prefer the password-less overload.

---

#### `ExportToPfxRawData`

```csharp
public static ErrorOr<byte[]> ExportToPfxRawData(X509Certificate2 certificate, string password)
```

Exports the certificate **including its private key** as PFX/PKCS#12 raw bytes, protected by `password`. The result can later be re-imported with [`GetFromRawData`](#getfromrawdata) or [`GetFromFile`](#getfromfile).

The protection depends on the target framework:

| Target | Key and certificate | MAC | Iterations |
|--------|---------------------|-----|------------|
| `net10.0`, `net11.0` | PBES2: PBKDF2 with HMAC-SHA-256, AES-256-CBC (`ExportPkcs12` with `Pkcs12ExportPbeParameters.Pbes2Aes256Sha256`) | SHA-256 | 2,000 |
| `net8.0`, `net9.0` | Legacy `pbeWithSHAAnd3-KeyTripleDES-CBC` (these frameworks have no `ExportPkcs12`) | SHA-1 | 2,000 |

(OpenSSL `pkcs12 -info` on exports made on Windows.) Current Windows, .NET and OpenSSL read both forms; an old importer that reads only the TripleDES form cannot read an export made on `net10.0` or later.

**Example**

```csharp
X509Certificate2 certificate = CertificateFactory.GetForLocalhost("CN=localhost", "Dev").Value;

ErrorOr<byte[]> pfx = CertificateFactory.ExportToPfxRawData(certificate, "S3cr3t!Passw0rd");
if (!pfx.IsError)
    File.WriteAllBytes("mycert.pfx", pfx.Value);
```

---

#### `ExportToCerFile`

```csharp
public static ErrorOr<byte[]> ExportToCerFile(X509Certificate2 certificate)
```

Exports the **public certificate only** (no private key) as DER-encoded `.cer` bytes. This is the file you distribute to clients that need to *trust* your certificate.

**Example**

```csharp
ErrorOr<byte[]> cer = CertificateFactory.ExportToCerFile(certificate);
if (!cer.IsError)
{
    File.WriteAllBytes("mycert.cer", cer.Value);

    // Re-loading the .cer yields a certificate WITHOUT a private key
    // (net9.0 and later; on net8.0 use new X509Certificate2(cer.Value)):
    var publicOnly = X509CertificateLoader.LoadCertificate(cer.Value);
    Console.WriteLine(publicOnly.HasPrivateKey); // False
}
```

---

#### `GetForLocalhost`

```csharp
public static ErrorOr<X509Certificate2> GetForLocalhost(string subject, string friendlyName, int keySize = 2048)
```

Convenience method that creates a self-signed certificate already valid (`NotBefore = yesterday`) and effectively **non-expiring** (`NotAfter` = 9999-12-31 23:59:59 UTC, in every time zone), with the default `localhost` / loopback SAN entries. Ideal for local HTTPS during development.

> **Reading `NotAfter` east of UTC:** `X509Certificate2.NotAfter` is local time, and 9999-12-31 23:59:59 UTC is beyond the last local time a `DateTime` can hold east of UTC, so there the property returns `DateTime.MaxValue` (and `.ToUniversalTime()` of it is earlier by the offset). The time in the certificate itself is 23:59:59 UTC.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `subject` | `string` | The subject name (e.g. `"CN=localhost"`). |
| `friendlyName` | `string` | The Windows friendly name. |
| `keySize` | `int` | RSA key size in bits. Defaults to `2048`. |

**Example**

```csharp
ErrorOr<X509Certificate2> result = CertificateFactory.GetForLocalhost(
    subject: "CN=localhost",
    friendlyName: "Local Dev HTTPS");

Console.WriteLine(result.Value.NotAfter.Year); // 9999
```

---

#### `GetFromRawData`

```csharp
public static ErrorOr<X509Certificate2> GetFromRawData(
    byte[] certificateData,
    string password,
    X509KeyStorageFlags keyStorageFlags =
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet)
```

Loads a certificate (with private key) from PFX/PKCS#12 raw bytes, by default with
`Exportable | PersistKeySet | MachineKeySet`, so the private key stays in the machine key store (see [Notes](#notes-gotchas--platform-behaviour)). The inverse of [`ExportToPfxRawData`](#exporttopfxrawdata).

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `certificateData` | `byte[]` | The PFX/PKCS#12 bytes. |
| `password` | `string` | The PFX password. |
| `keyStorageFlags` | `X509KeyStorageFlags` | The storage flags of the load. The default persists the private key in the machine key store, as a Windows TLS server (SChannel) and a key shared across processes need. `X509KeyStorageFlags.EphemeralKeySet` keeps it in memory only and writes nothing to disk (not on macOS). A combination the platform rejects (for example `EphemeralKeySet` with `PersistKeySet`) is returned as an `ErrorType.Unexpected` error. |

**Example**

```csharp
byte[] pfxBytes = File.ReadAllBytes("mycert.pfx");

ErrorOr<X509Certificate2> result = CertificateFactory.GetFromRawData(pfxBytes, "S3cr3t!Passw0rd");

// A wrong password does not throw — it returns an ErrorType.Unexpected error:
if (result.IsError)
    Console.WriteLine(result.FirstError.Type); // Unexpected
else
    Console.WriteLine(result.Value.HasPrivateKey); // True
```

---

#### `GetFromFile`

```csharp
public static ErrorOr<X509Certificate2> GetFromFile(
    string certificateFile,
    string? password,
    X509KeyStorageFlags keyStorageFlags =
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet)
```

Loads a certificate (with private key) directly from a PFX file on disk, with the same default flags as [`GetFromRawData`](#getfromrawdata), so the private key stays in the machine key store. The `password` may be `null` for a password-less PFX. A missing file or wrong password is returned as an `ErrorType.Unexpected` error rather than thrown.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `certificateFile` | `string` | Path to the `.pfx` file. |
| `password` | `string?` | The PFX password, or `null` if the file is not password-protected. |
| `keyStorageFlags` | `X509KeyStorageFlags` | The storage flags of the load, as in [`GetFromRawData`](#getfromrawdata). |

**Example (a key in memory only)**

```csharp
ErrorOr<X509Certificate2> inMemory = CertificateFactory.GetFromFile(
    "mycert.pfx", "S3cr3t!Passw0rd", X509KeyStorageFlags.EphemeralKeySet);
```

**Example**

```csharp
ErrorOr<X509Certificate2> result = CertificateFactory.GetFromFile("mycert.pfx", "S3cr3t!Passw0rd");

result.Switch(
    cert  => Console.WriteLine($"Loaded {cert.Thumbprint}"),
    errs  => Console.WriteLine($"Could not load: {errs[0].Type}"));
```

---

### `CertificateAccess`

> `public static class CertificateAccess`

Accesses and manages certificates in the OS certificate store, and reads a certificate's Subject Alternative Names. All read methods open the store **read-only**; `AddToStore`/`RemoveFromStore` open it **read-write**.

| Member | Returns | Summary |
|--------|---------|---------|
| `AddToStore(X509Certificate2, StoreName, StoreLocation)` | `ErrorOr<Success>` | Add a certificate to a store. |
| `FindByThumbprint(StoreName, StoreLocation, string)` | `ErrorOr<X509Certificate2>` | Find a certificate by thumbprint (or `NotFound`). |
| `GetAllFromStore(StoreName, StoreLocation)` | `ErrorOr<IEnumerable<X509Certificate2>>` | Return every certificate in a store. |
| `FindByDnsNames(StoreName, StoreLocation, IEnumerable<string>)` | `ErrorOr<IEnumerable<X509Certificate2>>` | Find certificates whose SANs contain **all** of the given DNS names. |
| `GetAlternateNames(X509Certificate2)` | `ErrorOr<IEnumerable<string>>` | Read the IP-address and DNS-name SAN entries of a certificate. |
| `RemoveFromStore(string, StoreName, StoreLocation)` | `ErrorOr<Success>` | Remove a certificate by thumbprint (no-op if absent). |

`StoreName`, `StoreLocation` come from `System.Security.Cryptography.X509Certificates`; `Success` comes from `ErrorOr`.

---

#### `AddToStore`

```csharp
public static ErrorOr<Success> AddToStore(
    X509Certificate2 certificate,
    StoreName storeName,
    StoreLocation storeLocation)
```

Opens the specified store for read-write and adds the certificate.

**Example**

```csharp
ErrorOr<Success> result = CertificateAccess.AddToStore(
    certificate,
    StoreName.My,                 // the "Personal" store
    StoreLocation.CurrentUser);   // per-user — no admin rights required

if (result.IsError) Console.WriteLine(result.FirstError.Description);
```

> ⚠️ Writing to `StoreLocation.LocalMachine` requires **administrator** privileges. `StoreLocation.CurrentUser` does not.

---

#### `FindByThumbprint`

```csharp
public static ErrorOr<X509Certificate2> FindByThumbprint(
    StoreName storeName,
    StoreLocation storeLocation,
    string thumbprint)
```

Returns the certificate matching `thumbprint`, or an `ErrorType.NotFound` error if it is not present. The search is **not** restricted to valid certificates (expired/untrusted certificates are still returned).

**Example**

```csharp
ErrorOr<X509Certificate2> result = CertificateAccess.FindByThumbprint(
    StoreName.My,
    StoreLocation.CurrentUser,
    certificate.Thumbprint);

if (!result.IsError)
    Console.WriteLine($"Found: {result.Value.Subject}");
else if (result.FirstError.Type == ErrorType.NotFound)
    Console.WriteLine("No certificate with that thumbprint.");
```

---

#### `GetAllFromStore`

```csharp
public static ErrorOr<IEnumerable<X509Certificate2>> GetAllFromStore(
    StoreName storeName,
    StoreLocation storeLocation)
```

Returns **all** certificates currently in the store as a materialised list.

**Example**

```csharp
ErrorOr<IEnumerable<X509Certificate2>> result = CertificateAccess.GetAllFromStore(
    StoreName.My,
    StoreLocation.CurrentUser);

foreach (X509Certificate2 cert in result.Value)
    Console.WriteLine($"{cert.Subject}  ({cert.Thumbprint})");
```

---

#### `FindByDnsNames`

```csharp
public static ErrorOr<IEnumerable<X509Certificate2>> FindByDnsNames(
    StoreName storeName,
    StoreLocation storeLocation,
    IEnumerable<string> dnsEntries)
```

Returns every certificate in the store whose Subject Alternative Names contain **all** of the requested entries. Matching is **case-insensitive**. Because the comparison uses `All`, a certificate is returned only if it covers every name you pass.

**Example**

```csharp
// Certificates that are valid for BOTH names:
ErrorOr<IEnumerable<X509Certificate2>> result = CertificateAccess.FindByDnsNames(
    StoreName.My,
    StoreLocation.CurrentUser,
    new[] { "myapp.local", "api.myapp.local" });

foreach (X509Certificate2 cert in result.Value)
    Console.WriteLine(cert.Thumbprint);
```

---

#### `GetAlternateNames`

```csharp
public static ErrorOr<IEnumerable<string>> GetAlternateNames(X509Certificate2 certificate)
```

Reads the certificate's SAN extension and returns its IP-address entries (rendered via `IPAddress.ToString()`) followed by its DNS-name entries, each group in the extension's order; in a certificate of this package your custom entries come before the defaults. A certificate with **no** SAN extension yields a successful, empty sequence.

**Example**

```csharp
ErrorOr<IEnumerable<string>> result = CertificateAccess.GetAlternateNames(certificate);

foreach (string name in result.Value)
    Console.WriteLine(name);

// Output for a certificate created with the custom entry "myapp.local":
// 127.0.0.1
// ::1
// 0.0.0.0
// ::
// 0.0.0.0
// myapp.local
// localhost
// MACHINENAME
```

---

#### `RemoveFromStore`

```csharp
public static ErrorOr<Success> RemoveFromStore(
    string thumbprint,
    StoreName storeName,
    StoreLocation storeLocation)
```

Opens the store for read-write and removes the certificate identified by `thumbprint`. If no such certificate exists, the call is a harmless **no-op** that still reports success.

**Example**

```csharp
ErrorOr<Success> result = CertificateAccess.RemoveFromStore(
    certificate.Thumbprint,
    StoreName.My,
    StoreLocation.CurrentUser);
```

---

### `AesCryptography`

> `public static class AesCryptography`

Derives AES keys with **PBKDF2** and encrypts strings into one of two payload formats:

- **Authenticated (use this):** [`AesGcmEncrypt`](#aesgcmencrypt) writes `"v2:<iterations>:<base64 salt>:<base64 nonce>:<base64 ciphertext and tag>"` with AES-256-GCM. The payload records its parameters, and [`AesGcmDecrypt`](#aesgcmdecrypt) reports a wrong password or a changed payload as an error.
- **Legacy:** [`AesEncrypt`](#aesencrypt) (obsolete) writes `"<base64 IV>:<base64 ciphertext>"` with AES-CBC and no integrity protection.

[`AesDecrypt`](#aesdecrypt) reads both, so data written in either format keeps decrypting.

| Member | Returns | Summary |
|--------|---------|---------|
| `MakeAESKey(string, string, HashAlgorithmName?, int, int)` | `ErrorOr<byte[]>` | Derive a key from a password + salt using PBKDF2. |
| `AesGcmEncrypt(string, string, int?)` | `ErrorOr<string>` | Encrypt a string into the authenticated `"v2:..."` format. |
| `AesGcmDecrypt(string, string)` | `ErrorOr<string>` | Decrypt a `"v2:..."` payload; an error on any failure. |
| `AesEncrypt(string, string, HashAlgorithmName?, int, int)` | `ErrorOr<string>` | *Obsolete.* Encrypt a string into the legacy `"iv:ciphertext"` format. |
| `AesDecrypt(string, string, HashAlgorithmName?, int, int)` | `ErrorOr<string>` | Decrypt a payload of either format; the input back on any failure. |
| `Iterations` (constant) | `int` | `100000`: the default PBKDF2 iteration count of `MakeAESKey` and the legacy format. |
| `DefaultOutputLength` (constant) | `int` | `32`: the default key length in bytes (AES-256) of `MakeAESKey` and the legacy format. |

Defaults of `MakeAESKey`, `AesEncrypt` and `AesDecrypt`: `hashAlgorithmName = SHA-256`, `outputLength = DefaultOutputLength` (32 bytes, AES-256), `iterations = Iterations` (100 000). Both are `const`, and optional-parameter defaults are compiled into the calling assembly: a different value in a later package version reaches your code only when you recompile.

The legacy payload does not record these parameters: decrypt it with the same `hashAlgorithmName`, `outputLength` and `iterations` you encrypted with.

**Moving to the authenticated format.** Encrypt new data with `AesGcmEncrypt`. Keep decrypting with `AesDecrypt`, which reads both formats, or switch to `AesGcmDecrypt` once every stored value is in the new format. To convert a stored value, decrypt it with `AesDecrypt` and encrypt the result with `AesGcmEncrypt`. A package version without `AesGcmEncrypt` cannot read the new format: its `AesDecrypt` returns such a payload unchanged.

---

#### `MakeAESKey`

```csharp
public static ErrorOr<byte[]> MakeAESKey(
    string password,
    string salt,
    HashAlgorithmName? hashAlgorithmName = null,
    int outputLength = 32,
    int iterations = 100000)
```

Derives a symmetric key from `password` and `salt` using PBKDF2. Deterministic: the same inputs always produce the same key. A `null` password or salt returns an `ErrorType.Validation` error whose `Description` names the offending parameter.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `password` | `string` | The secret to derive the key from. |
| `salt` | `string` | The salt mixed into the derivation. |
| `hashAlgorithmName` | `HashAlgorithmName?` | The PBKDF2 PRF. Defaults to SHA-256 when `null`. |
| `outputLength` | `int` | Desired key length in bytes. Defaults to `32` (256-bit). |
| `iterations` | `int` | PBKDF2 iteration count. Defaults to `100000`. |

**Example**

```csharp
ErrorOr<byte[]> key = AesCryptography.MakeAESKey("correct horse", "a-pinch-of-salt");

if (!key.IsError)
    Console.WriteLine(key.Value.Length); // 32

// Validation error for a null password:
ErrorOr<byte[]> bad = AesCryptography.MakeAESKey(null!, "salt");
Console.WriteLine(bad.FirstError.Type);        // Validation
Console.WriteLine(bad.FirstError.Description);  // password
```

---

#### `AesEncrypt`

```csharp
public static ErrorOr<string> AesEncrypt(
    string password,
    string content,
    HashAlgorithmName? hashAlgorithmName = null,
    int outputLength = 32,
    int iterations = 100000)
```

> ⚠️ **Obsolete.** The payload is AES-CBC without integrity protection (see [Security notes](#security-notes)); use [`AesGcmEncrypt`](#aesgcmencrypt) for new data. A call raises warning CS0618, so a project that treats warnings as errors fails to build until it moves to `AesGcmEncrypt` or suppresses the warning. [`AesDecrypt`](#aesdecrypt) keeps reading what `AesEncrypt` wrote.

Encrypts `content` with an AES key derived from `password` (via [`MakeAESKey`](#makeaeskey)) and a fresh random IV, returning `"<base64 IV>:<base64 ciphertext>"`.

- `null` password → `ErrorType.Validation` (`Description = "password"`).
- `null`/empty/whitespace content → a successful **empty string** (nothing to encrypt).
- The same content encrypted twice yields **different** payloads (random IV).

> When using `AesEncrypt`/`AesDecrypt`, keep `outputLength` at a valid AES key size — `16`, `24` or `32` bytes — because the derived key is assigned to `Aes.Key`.

**Example**

```csharp
ErrorOr<string> encrypted = AesCryptography.AesEncrypt("p@ssword", "Hello, world!");

Console.WriteLine(encrypted.Value); // e.g. "Q2hhbmdlSVZ...=:8f2bniH4...=="
```

---

#### `AesDecrypt`

```csharp
public static ErrorOr<string> AesDecrypt(
    string password,
    string encryptedContent,
    HashAlgorithmName? hashAlgorithmName = null,
    int outputLength = 32,
    int iterations = 100000)
```

Decrypts a payload of either format:

- a `"<base64 IV>:<base64 ciphertext>"` string produced by [`AesEncrypt`](#aesencrypt), using the **same** password and key-derivation parameters;
- a `"v2:..."` payload produced by [`AesGcmEncrypt`](#aesgcmencrypt) (told apart by the prefix `v2:`), through [`AesGcmDecrypt`](#aesgcmdecrypt); the payload records its own parameters, so `hashAlgorithmName`, `outputLength` and `iterations` are ignored for it.

Failure handling is deliberately lenient — the only error path is a `null` password (`ErrorType.Validation`). For any non-null password:

- A correct password + valid payload → the original plaintext.
- `null`/empty/whitespace input → a successful **empty string**.
- Malformed input (not two colon-separated parts, and not a `v2:` payload) → returned **unchanged**.
- An undecodable payload (bad Base64, wrong lengths) → the original input is returned **unchanged**, thanks to the internal `.Else(...)` fallback.
- A `v2:` payload that `AesGcmDecrypt` rejects (a wrong password, a changed or malformed payload) → returned **unchanged**. Use `AesGcmDecrypt` itself to get the error.
- A legacy payload with a wrong password → usually the original input **unchanged**: the derived key is wrong, the padding check fails, and the fallback returns the input. In about 0.4 % of the cases (measured: 300 in 80,000 tries) the wrong key still leaves valid padding, and **other text** comes back as a success. The plaintext is never disclosed, but a success does not prove that the password was right: the legacy payload has no integrity check (see [Security notes](#security-notes)).

**Example**

```csharp
string payload = AesCryptography.AesEncrypt("p@ssword", "Hello, world!").Value;

// Correct password round-trips back to the plaintext:
ErrorOr<string> ok = AesCryptography.AesDecrypt("p@ssword", payload);
Console.WriteLine(ok.Value); // Hello, world!

// A wrong password never reveals the plaintext (it usually returns the input unchanged):
ErrorOr<string> wrong = AesCryptography.AesDecrypt("not-the-password", payload);
Console.WriteLine(wrong.Value == "Hello, world!"); // False

// The same call reads the authenticated format:
string v2 = AesCryptography.AesGcmEncrypt("p@ssword", "Hello, world!").Value;
Console.WriteLine(AesCryptography.AesDecrypt("p@ssword", v2).Value); // Hello, world!
```

---

#### `AesGcmEncrypt`

```csharp
public static ErrorOr<string> AesGcmEncrypt(
    string password,
    string content,
    int? iterations = null)
```

Encrypts `content` with AES-256-GCM into an authenticated payload:

```
v2:<iterations>:<base64 salt>:<base64 nonce>:<base64 ciphertext followed by the tag>
```

- The key is PBKDF2-HMAC-SHA256 of the UTF-8 `password` with a random 16-byte salt (32 bytes); the nonce is random (12 bytes), the tag 16 bytes.
- The version, the iteration count, the salt and the nonce are authenticated with the ciphertext (as associated data), so a change to any of them is detected.
- `iterations` is recorded in the payload: from `1` to `6,000,000`. `null` takes the library's current default, **600,000** (the OWASP figure for PBKDF2-HMAC-SHA256), applied at run time, so a later raise reaches your code without a recompile; existing payloads keep the count they were made with.
- Empty and whitespace-only content is encrypted too, and comes back exactly.
- The same content encrypted twice yields **different** payloads (random salt and nonce).

Errors:

| Case | Error |
|------|-------|
| `null` password or content | `ErrorType.Validation`, `Description` = the parameter's name |
| `iterations` below 1 or above 6,000,000 | `ErrorType.Validation`, `Description = "iterations"` |
| The platform has no AES-GCM (`AesGcm.IsSupported` is false) | `ErrorType.Failure`, `Code = "AesGcm.NotSupported"`; there is no fallback to the legacy format |

Every decryption runs PBKDF2 with the payload's iteration count: with the default, about 46 ms on a desktop Intel Core i9-14900KF; slower machines take longer.

**Example**

```csharp
ErrorOr<string> encrypted = AesCryptography.AesGcmEncrypt("p@ssword", "Hello, world!");

Console.WriteLine(encrypted.Value); // e.g. "v2:600000:x6y+E1gT...==:KU8evXU1...:/878FRsu..."
```

---

#### `AesGcmDecrypt`

```csharp
public static ErrorOr<string> AesGcmDecrypt(string password, string encryptedContent)
```

Decrypts a payload of [`AesGcmEncrypt`](#aesgcmencrypt). Unlike [`AesDecrypt`](#aesdecrypt), it reports every failure as an error, and never returns text for a wrong password or a changed payload:

| Case | Error |
|------|-------|
| `null` password or payload | `ErrorType.Validation`, `Description` = the parameter's name |
| Not a valid payload: not the `v2:` format, Base64 or lengths that do not fit, or an iteration count outside 1 to 6,000,000 (checked before the key is derived, so a payload cannot make a decryption run longer) | `ErrorType.Validation`, `Code = "AesGcm.InvalidPayload"` |
| A wrong password, or a changed payload | `ErrorType.Failure`, `Code = "AesGcm.AuthenticationFailed"` |
| The platform has no AES-GCM | `ErrorType.Failure`, `Code = "AesGcm.NotSupported"` |

No error carries the password, the key or any part of the plaintext.

**Example**

```csharp
string payload = AesCryptography.AesGcmEncrypt("p@ssword", "Hello, world!").Value;

ErrorOr<string> ok = AesCryptography.AesGcmDecrypt("p@ssword", payload);
Console.WriteLine(ok.Value); // Hello, world!

ErrorOr<string> wrong = AesCryptography.AesGcmDecrypt("not-the-password", payload);
Console.WriteLine(wrong.FirstError.Code); // AesGcm.AuthenticationFailed
```

---

## How Subject Alternative Names are built

When you call either `CreateSelfSigned` overload (and therefore `GetForLocalhost`), the SAN extension is assembled as follows:

1. **Your custom entries** (`dnsNames`) are processed one by one:
   - A value that parses as an **IP address** is added as an IP SAN — **unless** it is a loopback address (`127.0.0.1` / `::1`), which is skipped because it is added by default below.
   - The **reserved names** `localhost`, `*`, and the current **machine name** are skipped (also added by default below).
   - Anything else is added as a **DNS name**.
2. **A fixed set of default entries** is always appended:
   - IP addresses: `127.0.0.1`, `::1`, `0.0.0.0`, `::`, and `0.0.0.0` again (`IPAddress.Any`), so `0.0.0.0` appears **twice**.
   - DNS names: `localhost` and the current machine name.

The net effect: every generated certificate is automatically valid for loopback, "any" addresses, `localhost` and the local machine. The skip rules keep your copies of `127.0.0.1`, `::1`, `localhost`, `*` and the machine name out of the list; `0.0.0.0` and `::` are **not** skipped, so passing them adds them once more.

---

## End-to-end example

Create a certificate, persist it to a store, retrieve it, then clean up:

```csharp
using System.Security.Cryptography.X509Certificates;
using ErrorOr;
using Forge.Next.Security;

// 1. Create a self-signed certificate valid for an internal host name.
ErrorOr<X509Certificate2> created = CertificateFactory.CreateSelfSigned(
    x500: "CN=Orders Service",
    friendlyName: "Orders Service TLS",
    dnsNames: new[] { "orders.internal", "10.0.0.20" },
    startTime: DateTime.UtcNow.AddDays(-1),
    endTime: DateTime.UtcNow.AddYears(3));

if (created.IsError)
    return;

X509Certificate2 certificate = created.Value;

// 2. Persist it to the current user's personal store (no admin rights needed).
CertificateAccess.AddToStore(certificate, StoreName.My, StoreLocation.CurrentUser);

try
{
    // 3. Later, retrieve it by thumbprint...
    ErrorOr<X509Certificate2> loaded = CertificateAccess.FindByThumbprint(
        StoreName.My, StoreLocation.CurrentUser, certificate.Thumbprint);

    // ...or by the names it must cover.
    ErrorOr<IEnumerable<X509Certificate2>> byDns = CertificateAccess.FindByDnsNames(
        StoreName.My, StoreLocation.CurrentUser, new[] { "orders.internal" });

    // 4. Inspect what it is valid for.
    foreach (string san in CertificateAccess.GetAlternateNames(loaded.Value).Value)
        Console.WriteLine(san);

    // 5. Back it up to a password-protected PFX for safe keeping.
    ErrorOr<byte[]> pfx = CertificateFactory.ExportToPfxRawData(loaded.Value, "Backup#2024");
    if (!pfx.IsError)
        File.WriteAllBytes("orders-service.pfx", pfx.Value);
}
finally
{
    // 6. Clean up the store entry when you are done.
    CertificateAccess.RemoveFromStore(
        certificate.Thumbprint, StoreName.My, StoreLocation.CurrentUser);
}
```

Using a certificate to host HTTPS with Kestrel:

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(5001, listen =>
    {
        ErrorOr<X509Certificate2> cert = CertificateFactory.GetForLocalhost("CN=localhost", "Dev HTTPS");
        listen.UseHttps(cert.Value);
    });
});

var app = builder.Build();
app.MapGet("/", () => "Hello over HTTPS!");
app.Run();
```

Encrypting and decrypting a secret:

```csharp
string token = AesCryptography.AesGcmEncrypt("master-password", "api-key-12345").Value;
ErrorOr<string> back = AesCryptography.AesGcmDecrypt("master-password", token);
Console.WriteLine(back.IsError ? back.FirstError.Code : back.Value); // api-key-12345
```

---

## Notes, gotchas & platform behaviour

- **Exception-free:** expected failures are returned as `ErrorOr` errors, not thrown. Always check `IsError` (or use `Match`/`Switch`) before reading `.Value`.
- **Friendly names are Windows-only.** `friendlyName` is applied only when running on Windows; on Linux/macOS the property is left empty (the certificate is otherwise identical).
- **`MachineKeySet` may require elevation, and the keys stay.** The password-based `CreateSelfSigned`, `GetFromRawData` and `GetFromFile` import keys, by default, with `Exportable | PersistKeySet | MachineKeySet`; pass `keyStorageFlags: X509KeyStorageFlags.EphemeralKeySet` where an in-memory key is enough (not for a TLS server on Windows, not on macOS). On Windows this writes the private key to the machine key store (a file in `C:\ProgramData\Microsoft\Crypto\Keys`) and usually needs administrator rights; failures surface as `ErrorType.Unexpected`. The key file **stays there** after the certificate is disposed: every call adds one, and nothing in this package removes it. When you no longer need a key, and no certificate in a store still uses it, delete it yourself:

  ```csharp
  using RSA? rsa = certificate.GetRSAPrivateKey();
  if (OperatingSystem.IsWindows() && rsa is RSACng cng)
      cng.Key.Delete(); // removes the key file; the certificate can no longer use its private key
  ```
- **`net8.0` also loads DER files.** On `net8.0`, `GetFromRawData` and `GetFromFile` also accept a DER certificate (a `.cer`) and return it without a private key; from `net9.0` they accept PKCS#12/PFX only and return an `ErrorType.Unexpected` error for DER.
- **Store write permissions.** `AddToStore`/`RemoveFromStore` against `StoreLocation.CurrentUser` work without elevation; `StoreLocation.LocalMachine` requires administrator rights.
- **Validity precision.** X.509 stores `NotBefore`/`NotAfter` with whole-second precision, so sub-second parts of your `DateTime` arguments are truncated.
- **`X509Certificate2.NotBefore` / `NotAfter` are returned in local time.** Convert with `.ToUniversalTime()` before comparing against UTC values.
- **AES key size.** Through `AesEncrypt`/`AesDecrypt` (the legacy format), `outputLength` must be `16`, `24` or `32` bytes (the derived key becomes `Aes.Key`). `MakeAESKey` on its own accepts any length.
- **`AesDecrypt` is lenient by design.** With a non-null password it never returns an error: a malformed payload, and almost every wrong password, yields the input unchanged rather than an exception, so it never leaks the plaintext but also will not tell you decryption "failed". For a legacy payload, comparing the result against the input catches most failures, not all: about 0.4 % of wrong passwords give other text (see [`AesDecrypt`](#aesdecrypt)). To get an error instead, use the authenticated format and [`AesGcmDecrypt`](#aesgcmdecrypt).
- **Disposal.** `X509Certificate2` is `IDisposable`. Dispose certificates you no longer need (e.g. with a `using` statement) to release key material promptly.

---

## Security notes

- **Use the authenticated AES format.** A payload of `AesGcmEncrypt` is AES-256-GCM: a wrong password or any change to the payload fails authentication, and `AesGcmDecrypt` reports it as an error. Its decryption accepts at most 6,000,000 PBKDF2 iterations and checks the count before deriving the key, so a crafted payload cannot make it run for long.
- **The legacy AES payload has no integrity protection.** `AesEncrypt` (obsolete) uses AES-CBC without a MAC, and `AesDecrypt` checks none for that format:
  - a changed payload can decrypt to changed text as a success (in a test, one flipped ciphertext bit changed one character of the next block);
  - a wrong password gives other text as a success in about 0.4 % of the cases (see [`AesDecrypt`](#aesdecrypt));
  - `AesDecrypt` answers differently to a bad padding (the input back) and a good one (other text), so do not let an untrusted party submit payloads to it and see the result: that makes a padding oracle possible.

  Move such data to `AesGcmEncrypt` (see [`AesCryptography`](#aescryptography)); until then keep the payloads where others cannot change them.
- **The PFX export's work factor is low.** `ExportToPfxRawData` protects the PFX with AES-256 on `net10.0` and later, and with the legacy TripleDES and SHA-1 on `net8.0` and `net9.0` (see [`ExportToPfxRawData`](#exporttopfxrawdata)); either way the password is stretched with only 2,000 iterations. A PFX with a weak password is cheap to attack offline: give a PFX you keep a long random password, and store it where others cannot read it.
- **Errors carry stack traces.** Every `ErrorType.Unexpected` error carries the exception's `type`, `message` and `stackTrace` in its `Metadata`. Before you send an error out of your process (an HTTP response, a message to another service), remove the metadata, or at least the `stackTrace`.
- **No secrets in this package's own errors.** The package logs nothing, and its `Validation` errors name the parameter, never its value.

---

## Testing

The repository contains an xUnit test suite under `tests/Forge.Next.Security.Tests` (xUnit + Shouldly + NSubstitute) that exercises the full public surface of all three classes on every target framework (`net8.0` to `net11.0`, so the four runtimes are needed). The PFX tests import keys with `MachineKeySet` (run them elevated on Windows) and delete the keys they create. Run it with:

```bash
dotnet test
```

---

## Keywords

Forge Patterns and Practices, Forge.Next, C#, .NET, .NET 8, .NET 9, .NET 10, .NET 11, NuGet package,
ErrorOr, result pattern, result-based error handling, functional error handling, C# cryptography
library, .NET security library, X.509 certificate management, self-signed certificates, certificate
generation, localhost HTTPS certificates, TLS certificates, SSL certificates, Subject Alternative
Name, SAN, RSA, SHA-256, certificate store, certificate thumbprint, DNS names, PFX, PKCS#12, DER,
CER certificate export, AES-256-GCM, authenticated encryption, symmetric encryption, password-based
encryption, PBKDF2 key derivation, legacy AES-CBC migration, ASP.NET Core, Kestrel, cross-platform
cryptography.

---

## License

Licensed under the **Apache-2.0** License. See the [license](https://github.com/JZO001/Forge.Next.Security#Apache-2.0-1-ov-file) for details.

Authored by **Zoltan Juhasz** — part of the *Forge Patterns and Practices* family.
