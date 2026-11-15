# Design

## The parts

All three classes are `public static`, in the `Forge.Next.Security` namespace. Every public method runs its work in
`Protect` (Forge.Next.Shared), so an exception becomes `Unexpected` errors.

| File | Type | Role |
| --- | --- | --- |
| `CertificateFactory.cs` | `CertificateFactory` | Self-signed certificates with a fixed profile and automatic SAN entries (two `CreateSelfSigned` overloads, `GetForLocalhost`); PFX and CER export; PFX loading from bytes or a file; the `Localhost` constant |
| `CertificateStore.cs` | `CertificateAccess` | The OS certificate store (add, find by thumbprint, list, find by DNS names, remove); a certificate's SAN entries (`GetAlternateNames`) |
| `AesCryptography.cs` | `AesCryptography` | PBKDF2 key derivation (`MakeAESKey`); authenticated AES-256-GCM encryption and decryption of strings (`AesGcmEncrypt`, `AesGcmDecrypt`); the legacy AES-CBC format (`AesEncrypt`, obsolete); `AesDecrypt`, which reads both formats; the `Iterations` and `DefaultOutputLength` constants |

## The targets

| Target | PFX loading (`#if NET8_0`) | Package references |
| --- | --- | --- |
| `net8.0` | the `X509Certificate2` constructor | `Forge.Next.Shared` 3.3.2 |
| `net9.0` | `X509CertificateLoader.LoadPkcs12` / `LoadPkcs12FromFile` | `Forge.Next.Shared` 3.3.2 |
| `net10.0` | `X509CertificateLoader.LoadPkcs12` / `LoadPkcs12FromFile` | `Forge.Next.Shared` 3.3.2 |
| `net11.0` (since 2026-11-15) | `X509CertificateLoader.LoadPkcs12` / `LoadPkcs12FromFile` | `Forge.Next.Shared` 3.3.2 |

**What differs on `net8.0`:** the constructor also loads a DER certificate. `GetFromFile` on a `.cer` file and
`GetFromRawData` on DER bytes succeed there (the public certificate, without a private key) and return an `Unexpected`
error on `net9.0`, `net10.0` and `net11.0` ("ASN1 corrupted data" in the probe of 2026-11-11). Since 2026-11-15 the tests
run on all four targets and pin each target's result (`GetFromRawData_DerData_Test`, `GetFromFile_CerFile_Test`).

Each target writes its own XML documentation file, `obj/<configuration>/<target>/Forge.Next.Security.xml`
(`GenerateDocumentationFile` without a `DocumentationFile` path, since 2026-11-15), and the package carries it as
`lib/<target>/Forge.Next.Security.xml`. Until then the project file named one file in the project folder for every
target, which the parallel target builds wrote at the same time (see `HISTORY.md`, 2026-11-15).

## The AES payloads

Two formats. `AesDecrypt` reads both and tells them apart by the prefix `v2:` (colon included): a legacy payload starts
with a 24-character Base64 IV, which starts with `v2` about once in 4,096 payloads but never holds a colon
(`AesDecrypt_CbcPayloadWhoseIvStartsWithV2_Test`).

### The authenticated format (since Release B)

`AesGcmEncrypt(password, content, iterations = null)`:
1. a null password or content: `Validation` error naming the parameter; an `iterations` outside 1 to 6,000,000:
   `Validation` error naming `iterations`; `AesGcm.IsSupported` false: `Failure` `AesGcm.NotSupported` (no fallback);
2. `null` iterations: the private constant `GcmDefaultIterations` (600,000), applied at run time, so a later raise needs
   no recompile of the callers; the payload records the count it was made with;
3. a random 16-byte salt and a random 12-byte nonce (`RandomNumberGenerator`);
4. the key: `Rfc2898DeriveBytes.Pbkdf2` of the UTF-8 password with the salt bytes, HMAC-SHA-256, 32 bytes; zeroed after
   use, with the plaintext bytes;
5. the header `v2:<iterations>:<Base64 salt>:<Base64 nonce>`, whose UTF-8 bytes are the associated data;
6. `new AesGcm(key, 16)`, `Encrypt`: the ciphertext (as long as the UTF-8 content) followed by the 16-byte tag;
7. the result: `<header>:<Base64 ciphertext and tag>`. Empty and whitespace-only content is encrypted too.

`AesGcmDecrypt(password, encryptedContent)` returns errors, never the input:
1. a null argument: `Validation` naming it; `AesGcm.IsSupported` false: `Failure` `AesGcm.NotSupported`;
2. parsing (`AesGcm.InvalidPayload`, `Validation`, on any mismatch): the prefix `v2:`, exactly five parts, the iteration
   count as plain digits (`NumberStyles.None`) from 1 to 6,000,000, checked before PBKDF2 runs (the DoS bound), then
   Base64 (`Convert.TryFromBase64String`, no exception) of a 16-byte salt, a 12-byte nonce and at least the 16-byte tag;
3. the associated data is the payload's own text before the last colon, not a rebuilt one, so any textual change of the
   header fails authentication;
4. `AuthenticationTagMismatchException` (in `System.Security.Cryptography` since .NET 8) becomes `Failure`
   `AesGcm.AuthenticationFailed`; anything else that throws becomes `Unexpected` through `Protect`.

`AesDecrypt` hands a `v2:` payload to `AesGcmDecrypt` and turns its every error into the unchanged input, so its contract
holds for both formats. An older package version's `AesDecrypt` splits a `v2:` payload into five parts and returns it
unchanged.

Measured (2026-11-15, Intel Core i9-14900KF, `net10.0`): one `AesGcmDecrypt` with 600,000 iterations 46 ms; one legacy
`AesDecrypt` with 100,000 iterations 8 ms.

### The legacy format

`AesEncrypt(password, content, hashAlgorithmName, outputLength, iterations)`, `[Obsolete]` since Release B (CS0618 at
every call; the tests of this format suppress it around their regions):
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
4. `CreateSelfSigned` with both times converted by the internal `ToUtcDateTimeOffset(time, TimeZoneInfo.Local)` (since
   Release B; visible to the tests through `InternalsVisibleTo`): a UTC time keeps its value, any other is local time
   (`zone.GetUtcOffset(time)`, which does not throw for a skipped daylight-saving time, as the former
   `new DateTimeOffset(time)` did not), and a result beyond `DateTime`'s range is clamped instead of throwing;
5. the friendly name, when `Environment.OSVersion.Platform` is `Win32NT`.

The certificate holds an ephemeral key; nothing is written to disk or to a store (on Windows the probe's calls left no
key file, 2026-11-11).

**The password overload:** the above, then `ExportToPfxRawData(certificate, password)` and
`GetFromRawData(pfx, password, keyStorageFlags)`. The three PFX loads (this overload, `GetFromRawData`, `GetFromFile`)
take an optional `keyStorageFlags` (since Release B) whose default is the private constant `PfxKeyStorageFlags`,
`Exportable | PersistKeySet | MachineKeySet`; both `#if NET8_0` branches pass it unchanged. With the default, on Windows
each load leaves the private key in the CNG machine key store, one file per load in `C:\ProgramData\Microsoft\Crypto\Keys`
(test run of 2026-11-11). The persisted default stays because SChannel needs it: a loopback `SslStream` server on
Windows failed the handshake with an ephemeral key (from `CertificateRequest`, or a PFX loaded with `EphemeralKeySet`:
"No credentials are available in the security package") and completed TLS 1.3 with a persisted one, in the user or the
machine key set (2026-11-15). `EphemeralKeySet` keeps the key in memory (`CngKey.IsEphemeral` is true on Windows); macOS
has no ephemeral key sets; a combination the platform rejects (`EphemeralKeySet | PersistKeySet`) is an `ArgumentException`,
so an `Unexpected` error.

**`ExportToPfxRawData`** (per target since Release B, `#if NET10_0_OR_GREATER`):
- `net10.0`, `net11.0`: `ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password)`: PBES2 with PBKDF2
  (HMAC-SHA-256) and AES-256-CBC for the key and the certificate, a SHA-256 MAC, 2,000 iterations;
- `net8.0`, `net9.0` (no `ExportPkcs12` in their reference packs): `Export(X509ContentType.Pfx, password)`: TripleDES
  with SHA-1, a SHA-1 MAC, 2,000 iterations.

All by OpenSSL on Windows exports (2026-11-15; the TripleDES form also 2026-11-11). The AES form loads with the
library on every target (the `net8.0` constructor through Windows' native import) and passes `certutil -dump`. The
iteration count is the preset's; `ExportPkcs12(PbeParameters, password)` would take another (an idea in `OPEN.md`).
**`ExportToCerFile`:** the DER encoding, without the private key.

**`GetForLocalhost(subject, friendlyName, keySize)`:** no caller entries, `NotBefore` one day before `DateTime.UtcNow`,
`NotAfter` `DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc)`: 9999-12-31 23:59:59Z in every time zone (since
Release B). Before, it passed a local `DateTime.MaxValue`: 22:59:59Z at +01:00, and an `Unexpected` error at -05:00.
East of UTC, `X509Certificate2.NotAfter` of such a certificate reads `DateTime.MaxValue` (local), because the encoded
time is beyond the last local `DateTime`; the tests read the encoded time from `RawData`.

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

- **The authenticated AES format, beside the legacy one** (Release B, `HISTORY.md` 2026-11-15): AES-GCM detects a
  wrong password and a changed payload; new methods instead of a changed `AesEncrypt`, so nothing changes for the
  current callers and an older package version still reads what `AesEncrypt` writes.

- **The PFX loads persist the key by default:** not recorded before; on 2026-11-15 a probe showed that SChannel needs a
  persisted key for a TLS server on Windows (see "The certificate"). The optional `keyStorageFlags` (B4) leaves the
  choice to the caller.

Not recorded anywhere: why the legacy format is AES-CBC without a MAC, why its IV doubles as the salt, and why 100,000
iterations.
