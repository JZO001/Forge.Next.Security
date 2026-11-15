# Design

## The parts

All three classes are `public static`, in the `Forge.Next.Security` namespace. Every public method runs its work in
`Protect` (Forge.Next.Shared), so an exception becomes `Unexpected` errors.

| File | Type | Role |
| --- | --- | --- |
| `CertificateFactory.cs` | `CertificateFactory` | Self-signed certificates with a fixed profile and automatic SAN entries (two `CreateSelfSigned` overloads, `GetForLocalhost`); PFX and CER export; PFX loading from bytes or a file; the `Localhost` constant |
| `CertificateStore.cs` | `CertificateAccess` | The OS certificate store (add, find by thumbprint, list, find by DNS names, remove); a certificate's SAN entries (`GetAlternateNames`) |
| `AesCryptography.cs` | `AesCryptography` | PBKDF2 key derivation (`MakeAESKey`); AES-CBC encryption and decryption of strings (`AesEncrypt`, `AesDecrypt`); the `Iterations` and `DefaultOutputLength` constants |

## The targets

| Target | PFX loading (`#if NET8_0`) | Package references |
| --- | --- | --- |
| `net8.0` | the `X509Certificate2` constructor | `Forge.Next.Shared` 3.3.2 |
| `net9.0` | `X509CertificateLoader.LoadPkcs12` / `LoadPkcs12FromFile` | `Forge.Next.Shared` 3.3.2 |
| `net10.0` | `X509CertificateLoader.LoadPkcs12` / `LoadPkcs12FromFile` | `Forge.Next.Shared` 3.3.2 |
| `net11.0` (since 2026-11-15) | `X509CertificateLoader.LoadPkcs12` / `LoadPkcs12FromFile` | `Forge.Next.Shared` 3.3.2 |

**What differs on `net8.0`:** the constructor also loads a DER certificate. `GetFromFile` on a `.cer` file succeeds
there (without a private key) and fails on `net10.0` ("ASN1 corrupted data"); checked with the probe on 2026-11-11 (see
`VERIFICATION.md`). `GetFromRawData` has the same split. The tests run only the `net10.0` build.

The project file writes the XML documentation to `Forge.Next.Security/Forge.Next.Security.xml` (a path relative to the
project, so in the source folder; ignored by git since 2026-07-01). The package carries it as
`lib/<target>/Forge.Next.Security.xml`. The four targets write that one file in parallel, which can put a
wrong file into a package (see `OPEN.md`).

## The AES payload

`AesEncrypt(password, content, hashAlgorithmName, outputLength, iterations)`:
1. a null password: `Validation` error; null, empty or whitespace-only content: `""`, a success;
2. `Aes.Create()`; its random 16-byte IV, as Base64 text, is also the PBKDF2 salt;
3. the key: `MakeAESKey(password, <IV as Base64>, …)`, that is `Rfc2898DeriveBytes.Pbkdf2` over the UTF-8 bytes of the
   password and of the salt text (defaults: SHA-256, 100,000 iterations, 32 bytes);
4. `EncryptCbc` over the UTF-8 bytes of the content, PKCS#7 padding;
5. the result: `<IV as Base64>:<ciphertext as Base64>`.

`AesDecrypt` reverses it. A null password: `Validation` error; null, empty or whitespace-only input: `""`; input that
does not split into exactly two parts at `:` is returned unchanged; any exception (Base64, the key length, the padding)
is turned into the unchanged input by the closing `.Else`. When a wrong password happens to leave valid padding, the
bytes are decoded as UTF-8 and returned as a success (see `OPEN.md`).

An `outputLength` that is not an AES key size (16, 24 or 32) makes `AesEncrypt` return an `Unexpected` error and
`AesDecrypt` return its input; `MakeAESKey` on its own derives other lengths too.

## The certificate

**`CreateSelfSigned` without a password:**
1. a null `x500` becomes an empty subject;
2. the SAN builder: each caller entry that parses as an IP address becomes an IP entry, except `127.0.0.1` and `::1`;
   `localhost`, `*` and the machine name are skipped (case-insensitively); anything else becomes a DNS entry; then the
   default entries: `127.0.0.1`, `::1`, `0.0.0.0`, `::`, `0.0.0.0` (`IPAddress.Parse("0.0.0.0")` and
   `IPAddress.Any`), `localhost`, the machine name;
3. `RSA.Create(keySize)`; a `CertificateRequest` with SHA-256 and PKCS#1 padding, and the non-critical extensions: key
   usage, the server authentication EKU, the SAN, basic constraints (not a CA), the subject key identifier;
4. `CreateSelfSigned(new DateTimeOffset(startTime), new DateTimeOffset(endTime))`: a `DateTime` that is not UTC gets
   the local offset;
5. the friendly name, when `Environment.OSVersion.Platform` is `Win32NT`.

The certificate holds an ephemeral key; nothing is written to disk or to a store (on Windows the probe's calls left no
key file, 2026-11-11).

**The password overload:** the above, then `ExportToPfxRawData(certificate, password)` and
`GetFromRawData(pfx, password)`, which loads with `Exportable | PersistKeySet | MachineKeySet`. `GetFromFile` loads with
the same flags. On Windows each such load leaves the private key in the machine key store: a test run on 2026-11-11 left
one file per load in `C:\ProgramData\Microsoft\Crypto\Keys` (see `VERIFICATION.md`).

**`ExportToPfxRawData`:** `Export(X509ContentType.Pfx, password)`. On Windows the result uses TripleDES with SHA-1 for
the key and the certificate, a SHA-1 MAC, and 2,000 iterations (OpenSSL, 2026-11-11). **`ExportToCerFile`:** the DER
encoding, without the private key.

**`GetForLocalhost(subject, friendlyName, keySize)`:** no caller entries, `NotBefore` one day before `DateTime.UtcNow`,
`NotAfter` `DateTime.MaxValue`. That value has no UTC kind, so step 4 gives it the local offset; where the offset is
negative, the conversion throws, and the call returns an `Unexpected` error (see `OPEN.md`).

## The store

- The read methods open the store `ReadOnly`; `AddToStore` and `RemoveFromStore` open it `ReadWrite`.
- `FindByThumbprint` and `RemoveFromStore` search with `validOnly: false` and take the first match.
  `FindByThumbprint` returns `NotFound` without a match; `RemoveFromStore` returns success.
- `GetAlternateNames` returns the IP entries (`IPAddress.ToString()`), then the DNS entries, each group in the
  extension's order; a certificate without the extension gives an empty list. For a certificate made with the custom
  entry `myapp.local`: `127.0.0.1, ::1, 0.0.0.0, ::, 0.0.0.0, myapp.local, localhost, <machine name>` (probe,
  2026-11-11).
- `FindByDnsNames` returns the certificates whose SAN entries, IP and DNS alike, contain every requested entry,
  compared in lower case. An empty request matches every certificate. When the SAN entries of one certificate cannot be
  read, the whole call returns that error.

## Why each choice was made

Where the history and the README give a reason:
- **`ErrorOr` results** (3.1.0): the README: "failures are values you handle explicitly rather than exceptions you have
  to catch". `Protect` is the bridge from the throwing .NET APIs.
- **`AesDecrypt` returns its input on failure** (3.1.0): the commit message: "so a wrong password never discloses the
  plaintext"; the README: "lenient by design", and a caller that needs to know compares the result with the input.
- **`#if NET8_0`:** `X509CertificateLoader` is not in the `net8.0` reference pack; from .NET 9 the loading constructors
  are obsolete (`SYSLIB0057`, in the `net9.0` and `net10.0` reference packs).
- **The friendly name on Windows only:** the README: "Friendly names are Windows-only". The guard is
  `Environment.OSVersion.Platform`, which the platform analyzer does not recognize, so the line suppresses CA1416.
- **The default SAN entries:** the README: "every generated certificate is automatically valid for loopback, "any"
  addresses, `localhost` and the local machine"; the skip rules keep the caller's copies of some of them out.
- **The password overload loads with `MachineKeySet`:** the README: "Use this overload when you need the private key
  persisted in the machine key store (for example, a Windows service that must access the key across
  processes/sessions)".
- **`GetForLocalhost` never expires:** the README: "Ideal for local HTTPS during development."

Not recorded anywhere: why AES-CBC without a MAC, why the IV doubles as the salt, why 100,000 iterations, and why
`GetFromRawData` and `GetFromFile` persist the key as well. These are questions in `OPEN.md`.
