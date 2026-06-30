# Forge.Next.Security

[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/JZO001/Forge.Next.Security#Apache-2.0-1-ov-file)

A small, focused .NET library for **X.509 certificate management** and **AES encryption** — with first-class support for self-signed certificates (local development, internal services, TLS endpoints) and password-based symmetric encryption.

Every public method returns an [`ErrorOr<T>`](https://github.com/amantinband/error-or) result instead of throwing, so failures are values you handle explicitly rather than exceptions you have to catch.

It is part of the **Forge Patterns and Practices** family.

---

## Table of contents

- [Features](#features)
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
- [How Subject Alternative Names are built](#how-subject-alternative-names-are-built)
- [End-to-end example](#end-to-end-example)
- [Notes, gotchas & platform behaviour](#notes-gotchas--platform-behaviour)
- [Testing](#testing)
- [License](#license)

---

## Features

- 🔐 **Self-signed certificate generation** with sensible, secure defaults (RSA 2048, SHA-256, TLS *Server Authentication* EKU) and a configurable key size.
- 🌐 **Automatic Subject Alternative Names (SAN)** — loopback, "any", `localhost` and the machine name are always included, plus any custom DNS names / IP addresses you supply.
- 💾 **Export & import** to/from PFX (PKCS#12) raw bytes or files, and export the public certificate as a `.cer` (DER) file.
- 🗄️ **Certificate store management** — add, find (by thumbprint or by DNS name), enumerate and remove certificates from the Windows/OS certificate store.
- 🧂 **AES encryption** — PBKDF2 key derivation plus AES-CBC encrypt/decrypt with a compact `iv:ciphertext` payload.
- ✅ **Exception-free API** — every method returns `ErrorOr<T>`; nothing throws for expected failures.

All types live in the **`Forge.Next.Security`** namespace.

---

## Requirements

| | |
|---|---|
| **Target frameworks** | `net8.0`, `net9.0`, `net10.0` |
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
| [`AesCryptography`](#aescryptography) | Derive AES keys (PBKDF2) and encrypt/decrypt strings (AES-CBC). |

---

### `CertificateFactory`

> `public static class CertificateFactory`

Creates and manages self-signed certificates. Generated certificates use an **RSA** key (2048-bit by default, configurable), a **SHA-256/PKCS#1** signature, the **TLS Server Authentication** enhanced key usage (`1.3.6.1.5.5.7.3.1`), the `DigitalSignature | KeyEncipherment | DataEncipherment` key usages, and are flagged as **non-CA** (end-entity) certificates.

| Member | Returns | Summary |
|--------|---------|---------|
| `Localhost` | `const string` | The constant `"localhost"`. |
| `CreateSelfSigned(string, string, IEnumerable<string>, DateTime, DateTime, int)` | `ErrorOr<X509Certificate2>` | Create an in-memory self-signed certificate. |
| `CreateSelfSigned(string, string, IEnumerable<string>, DateTime, DateTime, string, int)` | `ErrorOr<X509Certificate2>` | Create a certificate and round-trip it through a password-protected PFX (machine key set). |
| `ExportToPfxRawData(X509Certificate2, string)` | `ErrorOr<byte[]>` | Export the certificate **and** private key as PFX bytes. |
| `ExportToCerFile(X509Certificate2)` | `ErrorOr<byte[]>` | Export the **public** certificate as DER (`.cer`) bytes. |
| `GetForLocalhost(string, string, int)` | `ErrorOr<X509Certificate2>` | Create a long-lived certificate for `localhost`. |
| `GetFromRawData(byte[], string)` | `ErrorOr<X509Certificate2>` | Load a certificate from PFX bytes. |
| `GetFromFile(string, string?)` | `ErrorOr<X509Certificate2>` | Load a certificate from a PFX file. |

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
| `startTime` | `DateTime` | Validity start (`NotBefore`). |
| `endTime` | `DateTime` | Validity end (`NotAfter`). |
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
    int keySize = 2048)
```

Same as the overload above, but after creation the certificate is **exported to a password-protected PFX and re-imported** with `X509KeyStorageFlags.Exportable | PersistKeySet | MachineKeySet`. Use this overload when you need the private key persisted in the **machine key store** (for example, a Windows service that must access the key across processes/sessions).

**Parameters** — identical to the overload above, plus a `password` (the password protecting the intermediate PFX round-trip), with `keySize` moving to the final position.

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

    // Re-loading the .cer yields a certificate WITHOUT a private key:
    var publicOnly = X509CertificateLoader.LoadCertificate(cer.Value);
    Console.WriteLine(publicOnly.HasPrivateKey); // False
}
```

---

#### `GetForLocalhost`

```csharp
public static ErrorOr<X509Certificate2> GetForLocalhost(string subject, string friendlyName, int keySize = 2048)
```

Convenience method that creates a self-signed certificate already valid (`NotBefore = yesterday`) and effectively **non-expiring** (`NotAfter = DateTime.MaxValue`, i.e. the year 9999), with the default `localhost` / loopback SAN entries. Ideal for local HTTPS during development.

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
public static ErrorOr<X509Certificate2> GetFromRawData(byte[] certificateData, string password)
```

Loads a certificate (with private key) from PFX/PKCS#12 raw bytes using
`Exportable | PersistKeySet | MachineKeySet`. The inverse of [`ExportToPfxRawData`](#exporttopfxrawdata).

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
public static ErrorOr<X509Certificate2> GetFromFile(string certificateFile, string? password)
```

Loads a certificate (with private key) directly from a PFX file on disk. The `password` may be `null` for a password-less PFX. A missing file or wrong password is returned as an `ErrorType.Unexpected` error rather than thrown.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `certificateFile` | `string` | Path to the `.pfx` file. |
| `password` | `string?` | The PFX password, or `null` if the file is not password-protected. |

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

Reads the certificate's SAN extension and returns its IP-address entries (rendered via `IPAddress.ToString()`) followed by its DNS-name entries. A certificate with **no** SAN extension yields a successful, empty sequence.

**Example**

```csharp
ErrorOr<IEnumerable<string>> result = CertificateAccess.GetAlternateNames(certificate);

foreach (string name in result.Value)
    Console.WriteLine(name);

// Typical output for a freshly created certificate:
// 127.0.0.1
// ::1
// 0.0.0.0
// ::
// 0.0.0.0
// localhost
// MACHINENAME
// myapp.local
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

Derives AES keys with **PBKDF2** and performs **AES-CBC** encryption/decryption of strings. Encrypted output is a compact `"<base64 IV>:<base64 ciphertext>"` string; a fresh random IV is generated for every `AesEncrypt` call.

| Member | Returns | Summary |
|--------|---------|---------|
| `MakeAESKey(string, string, HashAlgorithmName?, int, int)` | `ErrorOr<byte[]>` | Derive a key from a password + salt using PBKDF2. |
| `AesEncrypt(string, string, HashAlgorithmName?, int, int)` | `ErrorOr<string>` | Encrypt a string; returns `"iv:ciphertext"`. |
| `AesDecrypt(string, string, HashAlgorithmName?, int, int)` | `ErrorOr<string>` | Decrypt an `"iv:ciphertext"` string. |

Defaults: `hashAlgorithmName = SHA-256`, `outputLength = 32` bytes (AES-256), `iterations = 100 000`.

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

Decrypts a `"<base64 IV>:<base64 ciphertext>"` string produced by [`AesEncrypt`](#aesencrypt), using the **same** password and key-derivation parameters.

Failure handling is deliberately lenient — the only error path is a `null` password (`ErrorType.Validation`). For any non-null password:

- A correct password + valid payload → the original plaintext.
- `null`/empty/whitespace input → a successful **empty string**.
- Malformed input (not two colon-separated parts) → returned **unchanged**.
- A wrong password or undecodable payload → the original input is returned **unchanged** (the plaintext is never disclosed), thanks to the internal `.Else(...)` fallback.

**Example**

```csharp
string payload = AesCryptography.AesEncrypt("p@ssword", "Hello, world!").Value;

// Correct password round-trips back to the plaintext:
ErrorOr<string> ok = AesCryptography.AesDecrypt("p@ssword", payload);
Console.WriteLine(ok.Value); // Hello, world!

// Wrong password never reveals the plaintext (returns the input unchanged):
ErrorOr<string> wrong = AesCryptography.AesDecrypt("not-the-password", payload);
Console.WriteLine(wrong.Value == "Hello, world!"); // False
```

---

## How Subject Alternative Names are built

When you call either `CreateSelfSigned` overload (and therefore `GetForLocalhost`), the SAN extension is assembled as follows:

1. **Your custom entries** (`dnsNames`) are processed one by one:
   - A value that parses as an **IP address** is added as an IP SAN — **unless** it is a loopback address (`127.0.0.1` / `::1`), which is skipped because it is added by default below.
   - The **reserved names** `localhost`, `*`, and the current **machine name** are skipped (also added by default below).
   - Anything else is added as a **DNS name**.
2. **A fixed set of default entries** is always appended:
   - IP addresses: `127.0.0.1`, `::1`, `0.0.0.0`, `::`, and `0.0.0.0` (any).
   - DNS names: `localhost` and the current machine name.

The net effect: every generated certificate is automatically valid for loopback, "any" addresses, `localhost` and the local machine — and the skip rules ensure those defaults are never duplicated even if you pass them explicitly.

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
string token = AesCryptography.AesEncrypt("master-password", "api-key-12345").Value;
string back  = AesCryptography.AesDecrypt("master-password", token).Value;
Console.WriteLine(back); // api-key-12345
```

---

## Notes, gotchas & platform behaviour

- **Exception-free:** expected failures are returned as `ErrorOr` errors, not thrown. Always check `IsError` (or use `Match`/`Switch`) before reading `.Value`.
- **Friendly names are Windows-only.** `friendlyName` is applied only when running on Windows; on Linux/macOS the property is left empty (the certificate is otherwise identical).
- **`MachineKeySet` may require elevation.** The password-based `CreateSelfSigned`, `GetFromRawData` and `GetFromFile` import keys with `MachineKeySet`. On Windows this writes to the machine key container and usually needs administrator rights; failures surface as `ErrorType.Unexpected`.
- **Store write permissions.** `AddToStore`/`RemoveFromStore` against `StoreLocation.CurrentUser` work without elevation; `StoreLocation.LocalMachine` requires administrator rights.
- **Validity precision.** X.509 stores `NotBefore`/`NotAfter` with whole-second precision, so sub-second parts of your `DateTime` arguments are truncated.
- **`X509Certificate2.NotBefore` / `NotAfter` are returned in local time.** Convert with `.ToUniversalTime()` before comparing against UTC values.
- **AES key size.** Through `AesEncrypt`/`AesDecrypt`, `outputLength` must be `16`, `24` or `32` bytes (the derived key becomes `Aes.Key`). `MakeAESKey` on its own accepts any length.
- **`AesDecrypt` is lenient by design.** With a non-null password it never returns an error: a wrong password or malformed payload yields the input unchanged rather than an exception, so it never leaks the plaintext but also will not tell you decryption "failed" — compare the result against the input if you need to detect that.
- **Disposal.** `X509Certificate2` is `IDisposable`. Dispose certificates you no longer need (e.g. with a `using` statement) to release key material promptly.

---

## Testing

The repository contains an xUnit test suite under `tests/Forge.Next.Security.Tests` (xUnit + Shouldly + NSubstitute) that exercises the full public surface of all three classes. Run it with:

```bash
dotnet test
```

---

## License

Licensed under the **Apache-2.0** License. See the [license](https://github.com/JZO001/Forge.Next.Security#Apache-2.0-1-ov-file) for details.

Authored by **Zoltan Juhasz** — part of the *Forge Patterns and Practices* family.
