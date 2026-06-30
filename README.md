# Forge.Next.Security

[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/JZO001/Forge.Next.Security#Apache-2.0-1-ov-file)

A small, focused .NET library for **creating, exporting, importing and managing X.509 certificates** — with first-class support for self-signed certificates suitable for local development, internal services and TLS endpoints.

It is part of the **Forge Patterns and Practices** family and is distributed in the NuGet package **`Forge.Next.Security`**.

---

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Getting started](#getting-started)
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
- [How Subject Alternative Names are built](#how-subject-alternative-names-are-built)
- [End-to-end example](#end-to-end-example)
- [Notes, gotchas & platform behaviour](#notes-gotchas--platform-behaviour)
- [Testing](#testing)
- [License](#license)

---

## Features

- 🔐 **Self-signed certificate generation** with sensible, secure defaults (RSA 2048, SHA-256, TLS *Server Authentication* EKU).
- 🌐 **Automatic Subject Alternative Names (SAN)** — loopback, "any", `localhost` and the machine name are always included, plus any custom DNS names / IP addresses you supply.
- 💾 **Export & import** to/from PFX (PKCS#12) raw bytes or files, and export the public certificate as a `.cer` (DER) file.
- 🗄️ **Certificate store management** — add, find (by thumbprint or by DNS name), enumerate and remove certificates from the Windows/OS certificate store.
- 🧩 **Static, dependency-free helpers** — no configuration, no setup, just call the methods.

All types live in the **`Forge.Next.Security`** namespace.

---

## Requirements

| | |
|---|---|
| **Target frameworks** | `net8.0`, `net9.0`, `net10.0` |
| **Language** | C# 12 |
| **Platforms** | Cross-platform. Certificate-store and friendly-name features are richest on Windows (see [platform notes](#notes-gotchas--platform-behaviour)). |

---

## Installation

Install the package from NuGet (the assembly is published as **`Forge.Next.Security`**):

```bash
dotnet add package Forge.Next.Security
```

or via the Package Manager Console:

```powershell
Install-Package Forge.Next.Security
```

Then import the namespace:

```csharp
using Forge.Next.Security;
using System.Security.Cryptography.X509Certificates;
```

---

## Getting started

Create a development HTTPS certificate for `localhost` and use it immediately:

```csharp
using Forge.Next.Security;

// A certificate valid from yesterday until the year 9999, with localhost SANs.
var certificate = CertificateFactory.GetForLocalhost(
    subject: "CN=localhost",
    friendlyName: "My App – Local HTTPS");

Console.WriteLine(certificate.Subject);        // CN=localhost
Console.WriteLine(certificate.HasPrivateKey);  // True
```

---

## API reference

The library exposes two **static** classes, both in the `Forge.Next.Security` namespace:

| Class | Responsibility |
|-------|----------------|
| [`CertificateFactory`](#certificatefactory) | Create, export and import self-signed certificates. |
| [`CertificateAccess`](#certificateaccess) | Read from and write to the OS certificate store; inspect SAN entries. |

---

### `CertificateFactory`

> `public static class CertificateFactory`

Provides methods for creating and managing self-signed certificates. Generated certificates use a **2048-bit RSA** key, a **SHA-256/PKCS#1** signature, the **TLS Server Authentication** enhanced key usage (`1.3.6.1.5.5.7.3.1`), the `DigitalSignature | KeyEncipherment | DataEncipherment` key usages, and are flagged as **non-CA** (end-entity) certificates.

| Member | Returns | Summary |
|--------|---------|---------|
| `Localhost` | `const string` | The constant `"localhost"`. |
| `CreateSelfSigned(string, string, IEnumerable<string>, DateTime, DateTime)` | `X509Certificate2` | Create an in-memory self-signed certificate. |
| `CreateSelfSigned(string, string, IEnumerable<string>, DateTime, DateTime, string)` | `X509Certificate2` | Create a self-signed certificate and round-trip it through a password-protected PFX (machine key set). |
| `ExportToPfxRawData(X509Certificate2, string)` | `byte[]` | Export the certificate **and** private key as PFX bytes. |
| `ExportToCerFile(X509Certificate2)` | `byte[]` | Export the **public** certificate as DER (`.cer`) bytes. |
| `GetForLocalhost(string, string)` | `X509Certificate2` | Create a long-lived certificate for `localhost`. |
| `GetFromRawData(byte[], string)` | `X509Certificate2` | Load a certificate from PFX bytes. |
| `GetFromFile(string, string?)` | `X509Certificate2` | Load a certificate from a PFX file. |

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
public static X509Certificate2 CreateSelfSigned(
    string x500,
    string friendlyName,
    IEnumerable<string> dnsNames,
    DateTime startTime,
    DateTime endTime)
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

**Example**

```csharp
using System.Security.Cryptography.X509Certificates;
using Forge.Next.Security;

X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
    x500: "CN=My Company, O=My Company Ltd, C=US",
    friendlyName: "My Internal Service",
    dnsNames: new[] { "myapp.local", "api.myapp.local", "192.168.1.50" },
    startTime: DateTime.UtcNow.AddDays(-1),
    endTime: DateTime.UtcNow.AddYears(5));

Console.WriteLine(certificate.Subject);       // CN=My Company, O=My Company Ltd, C=US
Console.WriteLine(certificate.HasPrivateKey); // True

// The supplied names — plus the default loopback/localhost/machine-name entries — are present:
foreach (string san in CertificateAccess.GetAlternateNames(certificate))
    Console.WriteLine(san);
```

> 💡 Use `DateTime.UtcNow` for the validity boundaries so the encoded values are unambiguous across time zones.

---

#### `CreateSelfSigned` (with password)

```csharp
public static X509Certificate2 CreateSelfSigned(
    string x500,
    string friendlyName,
    IEnumerable<string> dnsNames,
    DateTime startTime,
    DateTime endTime,
    string password)
```

Same as the overload above, but after creation the certificate is **exported to a password-protected PFX and re-imported** using `X509KeyStorageFlags.Exportable | PersistKeySet | MachineKeySet`. Use this overload when you need the private key persisted in the **machine key store** (for example, a Windows service that must access the key across processes/sessions).

**Parameters** — identical to the overload above, plus:

| Name | Type | Description |
|------|------|-------------|
| `password` | `string` | The password protecting the intermediate PFX during the export/import round-trip. |

**Example**

```csharp
X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
    x500: "CN=My Windows Service",
    friendlyName: "My Service Certificate",
    dnsNames: new[] { "service.internal" },
    startTime: DateTime.UtcNow.AddDays(-1),
    endTime: DateTime.UtcNow.AddYears(2),
    password: "S3cr3t!Passw0rd");

Console.WriteLine(certificate.HasPrivateKey); // True
```

> ⚠️ **Permissions:** `MachineKeySet` writes to the machine-wide key container. On Windows this typically requires the process to run **elevated (as Administrator)**. If you only need an in-memory key, prefer the password-less overload.

---

#### `ExportToPfxRawData`

```csharp
public static byte[] ExportToPfxRawData(X509Certificate2 certificate, string password)
```

Exports the certificate **including its private key** as PFX/PKCS#12 raw bytes, protected by `password`. The result can later be re-imported with [`GetFromRawData`](#getfromrawdata) or [`GetFromFile`](#getfromfile).

**Example**

```csharp
byte[] pfxBytes = CertificateFactory.ExportToPfxRawData(certificate, "S3cr3t!Passw0rd");

// Persist it for later use:
File.WriteAllBytes("mycert.pfx", pfxBytes);
```

---

#### `ExportToCerFile`

```csharp
public static byte[] ExportToCerFile(X509Certificate2 certificate)
```

Exports the **public certificate only** (no private key) as DER-encoded `.cer` bytes. This is the file you distribute to clients that need to *trust* your certificate.

**Example**

```csharp
byte[] cerBytes = CertificateFactory.ExportToCerFile(certificate);
File.WriteAllBytes("mycert.cer", cerBytes);

// Re-loading the .cer yields a certificate WITHOUT a private key:
var publicOnly = X509CertificateLoader.LoadCertificate(cerBytes);
Console.WriteLine(publicOnly.HasPrivateKey); // False
```

---

#### `GetForLocalhost`

```csharp
public static X509Certificate2 GetForLocalhost(string subject, string friendlyName)
```

Convenience method that creates a self-signed certificate already valid (`NotBefore = yesterday`) and effectively **non-expiring** (`NotAfter = DateTime.MaxValue`, i.e. the year 9999), with the default `localhost` / loopback SAN entries. Ideal for local HTTPS during development.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `subject` | `string` | The subject name (e.g. `"CN=localhost"` or `"CN=your company"`). |
| `friendlyName` | `string` | The Windows friendly name. |

**Example**

```csharp
X509Certificate2 certificate = CertificateFactory.GetForLocalhost(
    subject: "CN=localhost",
    friendlyName: "Local Dev HTTPS");

Console.WriteLine(certificate.NotAfter.Year); // 9999
```

---

#### `GetFromRawData`

```csharp
public static X509Certificate2 GetFromRawData(byte[] certificateData, string password)
```

Loads a certificate (with private key) from PFX/PKCS#12 raw bytes using
`Exportable | PersistKeySet | MachineKeySet`. The inverse of [`ExportToPfxRawData`](#exporttopfxrawdata).

**Example**

```csharp
byte[] pfxBytes = File.ReadAllBytes("mycert.pfx");

X509Certificate2 certificate = CertificateFactory.GetFromRawData(pfxBytes, "S3cr3t!Passw0rd");
Console.WriteLine(certificate.HasPrivateKey); // True
```

> An incorrect password throws a `System.Security.Cryptography.CryptographicException`.

---

#### `GetFromFile`

```csharp
public static X509Certificate2 GetFromFile(string certificateFile, string? password)
```

Loads a certificate (with private key) directly from a PFX file on disk. The `password` may be `null` for a password-less PFX.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `certificateFile` | `string` | Path to the `.pfx` file. |
| `password` | `string?` | The PFX password, or `null` if the file is not password-protected. |

**Example**

```csharp
X509Certificate2 certificate = CertificateFactory.GetFromFile("mycert.pfx", "S3cr3t!Passw0rd");

// Password-less file:
X509Certificate2 plain = CertificateFactory.GetFromFile("plain.pfx", null);
```

---

### `CertificateAccess`

> `public static class CertificateAccess`

Provides methods for accessing and managing certificates in the OS certificate store, plus a helper to read a certificate's Subject Alternative Names. All store-reading methods open the store **read-only**; `AddToStore` and `RemoveFromStore` open it **read-write**.

| Member | Returns | Summary |
|--------|---------|---------|
| `AddToStore(X509Certificate2, StoreName, StoreLocation)` | `void` | Add a certificate to a store. |
| `FindByThumbprint(StoreName, StoreLocation, string)` | `X509Certificate2?` | Find a single certificate by thumbprint (or `null`). |
| `GetAllFromStore(StoreName, StoreLocation)` | `IEnumerable<X509Certificate2>` | Return every certificate in a store. |
| `FindByDnsNames(StoreName, StoreLocation, IEnumerable<string>)` | `IEnumerable<X509Certificate2>` | Find certificates whose SANs contain **all** of the given DNS names. |
| `GetAlternateNames(X509Certificate2)` | `IEnumerable<string>` | Read the IP-address and DNS-name SAN entries of a certificate. |
| `RemoveFromStore(string, StoreName, StoreLocation)` | `void` | Remove a certificate by thumbprint (no-op if absent). |

`StoreName` and `StoreLocation` come from `System.Security.Cryptography.X509Certificates`.

---

#### `AddToStore`

```csharp
public static void AddToStore(
    X509Certificate2 certificate,
    StoreName storeName,
    StoreLocation storeLocation)
```

Opens the specified store for read-write and adds the certificate.

**Example**

```csharp
using System.Security.Cryptography.X509Certificates;
using Forge.Next.Security;

CertificateAccess.AddToStore(
    certificate,
    StoreName.My,                 // the "Personal" store
    StoreLocation.CurrentUser);   // per-user — no admin rights required
```

> ⚠️ Writing to `StoreLocation.LocalMachine` requires **administrator** privileges. `StoreLocation.CurrentUser` does not.

---

#### `FindByThumbprint`

```csharp
public static X509Certificate2? FindByThumbprint(
    StoreName storeName,
    StoreLocation storeLocation,
    string thumbprint)
```

Returns the certificate matching `thumbprint`, or `null` if it is not present. The search is **not** restricted to valid certificates (expired/untrusted certificates are still returned).

**Example**

```csharp
X509Certificate2? found = CertificateAccess.FindByThumbprint(
    StoreName.My,
    StoreLocation.CurrentUser,
    certificate.Thumbprint);

if (found is not null)
{
    Console.WriteLine($"Found: {found.Subject}");
}
```

---

#### `GetAllFromStore`

```csharp
public static IEnumerable<X509Certificate2> GetAllFromStore(
    StoreName storeName,
    StoreLocation storeLocation)
```

Returns **all** certificates currently in the store as a materialised list.

**Example**

```csharp
IEnumerable<X509Certificate2> all = CertificateAccess.GetAllFromStore(
    StoreName.My,
    StoreLocation.CurrentUser);

foreach (X509Certificate2 cert in all)
{
    Console.WriteLine($"{cert.Subject}  ({cert.Thumbprint})");
}
```

---

#### `FindByDnsNames`

```csharp
public static IEnumerable<X509Certificate2> FindByDnsNames(
    StoreName storeName,
    StoreLocation storeLocation,
    IEnumerable<string> dnsEntries)
```

Returns every certificate in the store whose Subject Alternative Names contain **all** of the requested entries. Matching is **case-insensitive**. Because the comparison uses `All`, a certificate is returned only if it covers every name you pass.

**Example**

```csharp
// Certificates that are valid for BOTH names:
IEnumerable<X509Certificate2> matches = CertificateAccess.FindByDnsNames(
    StoreName.My,
    StoreLocation.CurrentUser,
    new[] { "myapp.local", "api.myapp.local" });

foreach (X509Certificate2 cert in matches)
{
    Console.WriteLine(cert.Thumbprint);
}
```

---

#### `GetAlternateNames`

```csharp
public static IEnumerable<string> GetAlternateNames(X509Certificate2 certificate)
```

Reads the certificate's SAN extension and returns its IP-address entries (rendered via `IPAddress.ToString()`) followed by its DNS-name entries. If the certificate has **no** SAN extension, an empty sequence is returned.

**Example**

```csharp
IEnumerable<string> sans = CertificateAccess.GetAlternateNames(certificate);

foreach (string name in sans)
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
public static void RemoveFromStore(
    string thumbprint,
    StoreName storeName,
    StoreLocation storeLocation)
```

Opens the store for read-write and removes the certificate identified by `thumbprint`. If no such certificate exists, the call is a harmless **no-op**.

**Example**

```csharp
CertificateAccess.RemoveFromStore(
    certificate.Thumbprint,
    StoreName.My,
    StoreLocation.CurrentUser);
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

Create a certificate, persist it to a store, retrieve it, use it, then clean up:

```csharp
using System.Security.Cryptography.X509Certificates;
using Forge.Next.Security;

// 1. Create a self-signed certificate valid for an internal host name.
X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
    x500: "CN=Orders Service",
    friendlyName: "Orders Service TLS",
    dnsNames: new[] { "orders.internal", "10.0.0.20" },
    startTime: DateTime.UtcNow.AddDays(-1),
    endTime: DateTime.UtcNow.AddYears(3));

// 2. Persist it to the current user's personal store (no admin rights needed).
CertificateAccess.AddToStore(certificate, StoreName.My, StoreLocation.CurrentUser);

try
{
    // 3. Later, retrieve it by thumbprint...
    X509Certificate2? loaded = CertificateAccess.FindByThumbprint(
        StoreName.My, StoreLocation.CurrentUser, certificate.Thumbprint);

    // ...or by the names it must cover.
    var byDns = CertificateAccess.FindByDnsNames(
        StoreName.My, StoreLocation.CurrentUser, new[] { "orders.internal" });

    // 4. Inspect what it is valid for.
    foreach (string san in CertificateAccess.GetAlternateNames(loaded!))
        Console.WriteLine(san);

    // 5. Back it up to a password-protected PFX for safe keeping.
    byte[] pfx = CertificateFactory.ExportToPfxRawData(loaded!, "Backup#2024");
    File.WriteAllBytes("orders-service.pfx", pfx);
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
        listen.UseHttps(CertificateFactory.GetForLocalhost("CN=localhost", "Dev HTTPS"));
    });
});

var app = builder.Build();
app.MapGet("/", () => "Hello over HTTPS!");
app.Run();
```

---

## Notes, gotchas & platform behaviour

- **Friendly names are Windows-only.** `friendlyName` is applied only when running on Windows; on Linux/macOS the property is left empty (the certificate is otherwise identical).
- **`MachineKeySet` may require elevation.** The password-based `CreateSelfSigned`, `GetFromRawData` and `GetFromFile` import keys with `MachineKeySet`. On Windows this writes to the machine key container and usually needs administrator rights.
- **Store write permissions.** `AddToStore`/`RemoveFromStore` against `StoreLocation.CurrentUser` work without elevation; `StoreLocation.LocalMachine` requires administrator rights.
- **Validity precision.** X.509 stores `NotBefore`/`NotAfter` with whole-second precision, so sub-second parts of your `DateTime` arguments are truncated.
- **`X509Certificate2.NotBefore` / `NotAfter` are returned in local time.** Convert with `.ToUniversalTime()` before comparing against UTC values.
- **Wrong PFX password** throws `System.Security.Cryptography.CryptographicException`.
- **Disposal.** `X509Certificate2` is `IDisposable`. Dispose certificates you no longer need (e.g. with a `using` statement) to release key material promptly.

---

## Testing

The repository contains an xUnit test suite under `tests/Forge.Next.Security.Tests` that exercises the full public surface of both classes. Run it with:

```bash
dotnet test
```

---

## License

Licensed under the **Apache-2.0** License. See the [license](https://github.com/JZO001/Forge.Next.Security#Apache-2.0-1-ov-file) for details.

Authored by **Zoltan Juhasz** — part of the *Forge Patterns and Practices* family.
