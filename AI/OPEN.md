# Open items

As of 2026-11-11; updated 2026-11-15 (`net11.0`, Forge.Next.Shared 3.3.2). Close an item by moving its outcome into `HISTORY.md` (decisions) or `VERIFICATION.md` (checks), and
deleting it here.

The order and the way to fix them: `PLANS/RECOMMENDED_WAY_TO_FIX.md` (2026-11-12).

## Waiting for Zoltán

The security findings come first, the most important first. None is fixed: each fix changes behaviour, a format or a
default.

- **The AES payload has no integrity protection.** `AesEncrypt` is AES-CBC without a MAC, and `AesDecrypt` checks none.
  - Verified (probe, 2026-11-11): one flipped bit in the first ciphertext block of a three-block text decrypted with the
    right password to a success, the first block garbled and the same bit flipped in the second ("fox" → "gox").
  - From reading the code, not demonstrated: `AesDecrypt` returns its input when the padding check fails, and other
    text when it passes. A party who can submit modified payloads to a consumer's decryption and see which of the two
    came back has a CBC padding oracle on every block after the first (the IV is also the key's salt, so a changed IV
    changes the key). Each query costs one PBKDF2 run, which slows the attack, not stops it.
  - A wrong password is not always detected: in 300 of 80,000 tries (about 0.4 %) it left valid padding, and
    `AesDecrypt` returned other text as a success, not the unchanged input the README promises.
  - Options: AES-GCM (`AesGcm`, in the reference packs of all four targets), or HMAC-SHA-256 over the IV and the
    ciphertext with a key of its own (encrypt-then-MAC). Either needs a new payload format with a marker, and
    `AesDecrypt` must keep reading the current one. Recommended: AES-GCM behind a marker; a payload of the new format
    that fails authentication can then be reported, which also settles the wrong-password case.
- **`ExportToPfxRawData` uses legacy PKCS#12 protection:** TripleDES and SHA-1 for the key and the certificate, a SHA-1
  MAC, 2,000 iterations (OpenSSL, 2026-11-11; Windows, `net8.0` and `net10.0`). A PFX with a weak password is cheap to
  attack offline, and the README suggests keeping a PFX as a backup. `net10.0` and `net11.0` offer
  `ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password)`; the `net8.0` and `net9.0` reference packs have
  no `ExportPkcs12`. Open: whether a stronger export is wanted on `net10.0` and later, and what to do on the older
  targets.
- **Every PFX load persists an exportable private key in the machine key store, and nothing removes it.** The password
  overload of `CreateSelfSigned`, `GetFromRawData` and `GetFromFile` load with
  `Exportable | PersistKeySet | MachineKeySet`. On Windows each load leaves a key file: the test run of 2026-11-11 left
  four in `C:\ProgramData\Microsoft\Crypto\Keys` (the folder held 7,329 files before it). The README names the flags and
  says the loads write to the machine key container; it does not say that the keys stay there. Question: is the
  persistence intended for the two loaders as well? Options: an optional `X509KeyStorageFlags` parameter on the loaders,
  defaulting to the current flags (no behaviour change); or ephemeral keys by default (a breaking change). Either way
  the tests should stop leaving keys behind.
- **The PBKDF2 default:** 100,000 iterations of HMAC-SHA-256. For comparison, OWASP's Password Storage Cheat Sheet gives
  600,000 for PBKDF2-HMAC-SHA256 (not checked in this session). The count is not in the payload, and the default is
  compiled into the callers, so a new default needs the format marker of the first item. Question: keep 100,000?
- **The errors carry stack traces.** Every `Unexpected` error has the exception's stack trace in its metadata
  (`stackTrace`). Forge.Next.Shared 3.3.2, which the package references, offers `includeStackTrace`; the package does
  not use it. A consumer that sends an error out of its process must strip the trace itself, and the README does not
  say so. Options: a README note; or an optional `includeStackTrace` parameter (default `true`, the current behaviour).
- **`GetForLocalhost` fails in a time zone west of UTC.** `NotAfter` is `DateTime.MaxValue`, which has no UTC kind, so
  `new DateTimeOffset(endTime)` applies the local offset; with a negative offset the UTC time passes year 9999 and the
  constructor throws. Verified on Linux (2026-11-11): with `TZ=America/New_York` the call returns an `Unexpected` error
  and `GetForLocalhostTest` fails; with `TZ=UTC` both pass. A fix also moves `NotAfter` on machines east of UTC by their
  offset (today it is 9999-12-31 22:59:59Z at UTC+01:00), so it needs a decision.
- **The package carries no license.** The project file sets `<licenses>`, which is not an MSBuild or NuGet property;
  none of the packages checked (3.0.0 to 3.2.0 in `artifacts/`, and the builds of 2026-11-11 and 2026-11-15) has a
  license element.
  Forge.Next.Shared sets `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, and the `LICENSE` here is
  the same Apache License 2.0. Recommended: the same property here, in the next version.
- **The targets share one XML documentation file.** `<DocumentationFile>Forge.Next.Security.xml</DocumentationFile>`
  makes the target builds (four since 2026-11-15), which run in parallel, write one file in the project folder, and
  each target copies whatever is there at that moment into its output, which is what the package takes. The packages
  checked here (3.0.0 to 3.2.0, and the four-target build of 2026-11-15) are whole, because the targets document the
  same members. The same setting put an
  empty, a truncated or another target's file into packages of Forge.Next.Formatters and Forge.Next.Shared (checked
  2026-11-11). Recommended: remove the `DocumentationFile` line, so each target writes its own file under `obj/`, as
  Forge.Next.LocalWebShell does; the `None Remove="Forge.Next.Security.xml"` item and the `.gitignore` entry are then
  not needed.
- **The local 3.0.0 package; the published versions.** `artifacts/Forge.Next.Security.3.0.0.nupkg` (built 2026-06-30
  20:01, between the 3.0.0 and the 3.1.0 commits) holds an intermediate build: its DLL returns `ErrorOr` and references
  `Forge.Next.Shared` 3.0.0, while its README documents the throwing API of the 3.0.0 commit. Which versions are
  published is not known here: the local NuGet cache has none, and nuget.org was not asked. Do not publish the local
  3.0.0 file.
- **README statements that do not match the code:**
  - `AesDecrypt`: "A wrong password ... the original input is returned unchanged" holds in about 99.6 % of the cases
    (the first item);
  - "How Subject Alternative Names are built": "the skip rules ensure those defaults are never duplicated even if you
    pass them explicitly" is not true for `0.0.0.0` and `::`, which are not skipped; the default list itself holds
    `0.0.0.0` twice;
  - `GetAlternateNames`: the "typical output" lists the custom DNS name last; it comes first among the DNS entries;
  - the public constants `AesCryptography.Iterations` and `AesCryptography.DefaultOutputLength` are not documented;
  - the notes do not say that the loaded keys stay in the machine key store, or that `GetForLocalhost` fails west of
    UTC.
- **Testing the `net8.0`, `net9.0` and `net11.0` builds:** the test project targets `net10.0` only, so the `net8.0`
  branch of the PFX loading never runs in the tests. Recommended:
  `<TargetFrameworks>net8.0;net9.0;net10.0;net11.0</TargetFrameworks>`.

## Not verified yet

- **The `net8.0`, `net9.0` and `net11.0` builds** are compiled, not tested. The probe ran a few calls against the
  `net8.0` build.
- **A non-elevated Windows process:** the tests ran elevated. The README says the `MachineKeySet` loads usually need
  administrator rights.
- **Linux as a non-root user, and macOS:** the Linux run was as root; macOS was not tried.
- **The published versions:** which versions are on nuget.org, and whether they match the local packages.

## Ideas, not decided

- **`FindByDnsNames`** reassigns its `dnsEntries` parameter inside the loop (`dnsEntries = dnsEntries.Select(...)`), so
  each certificate adds one more `ToLowerInvariant` projection, and the work grows with the square of the store's size
  (not measured). Lower-casing the request once, before the loop, gives the same result. An empty request matches every
  certificate; the README does not say so.
- **Undisposed certificates:** `FindByThumbprint`, `FindByDnsNames` and `RemoveFromStore` read `store.Certificates`,
  which creates an `X509Certificate2` for every certificate in the store; those not returned are left to the finalizer.
  The ephemeral certificate inside the password overload is not disposed either.
- **A known-answer test for the AES payload:** a fixed payload and password of the current format, so a change to the
  format or a default fails a test instead of passing silently.
- **The `net8.0` PFX loading** also accepts a DER certificate (the probe loaded a `.cer` with `GetFromFile`); the other
  targets do not. Whether the difference should stay.
- **Whitespace-only content:** `AesEncrypt` turns it into `""`, so a decryption does not give it back. The README says
  so ("nothing to encrypt").
- **The platform guard:** `OperatingSystem.IsWindows()` instead of `Environment.OSVersion.Platform`, so the CA1416
  suppression can go.
- **`typeof(CertificateFactory)`** is the receiver of `Protect` in `AesCryptography`; `typeof(AesCryptography)` would
  read better. No behaviour depends on it.
- **The file name** `CertificateStore.cs` holds `CertificateAccess`, and its tests are `CertificateStoreTests`.
- **The XML documentation is thin:** empty `<returns>` elements, an `<exception cref="ArgumentException">` on a
  `CreateSelfSigned` overload that returns errors, and `AesEncrypt`'s "a base64-encoded string" for what is
  `<Base64 IV>:<Base64 ciphertext>`.
- **The `.nuspec`'s repository commit** names the commit before the release: the 3.1.0 package (built 2026-06-30
  20:33, the commit 20:34) names `e70ca0e4`, the 3.2.0 package (built 2026-11-02 15:29, the commit 15:30) names
  `3aaaea0d`: each was built just before its release commit.
