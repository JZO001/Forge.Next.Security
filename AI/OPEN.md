# Open items

As of 2026-11-11; updated 2026-11-15 (`net11.0`, Forge.Next.Shared 3.3.2). Close an item by moving its outcome into `HISTORY.md` (decisions) or `VERIFICATION.md` (checks), and
deleting it here.

The order and the way to fix them: `PLANS/RECOMMENDED_WAY_TO_FIX.md` (2026-11-12).

## Waiting for Zoltán

The security findings come first, the most important first. None is fixed: each fix changes behaviour, a format or a
default.

Decided on 2026-11-15 (`HISTORY.md`): the AES format, the PBKDF2 default, the PFX export, the key storage flags,
`GetForLocalhost` and the stack traces, each as `PLANS/RECOMMENDED_WAY_TO_FIX.md` recommends (B1 to B6). These items now
wait for their fix, not for an answer.

- **The AES payload has no integrity protection.** `AesEncrypt` is AES-CBC without a MAC, and `AesDecrypt` checks none.
  - Verified (probe, 2026-11-11): one flipped bit in the first ciphertext block of a three-block text decrypted with the
    right password to a success, the first block garbled and the same bit flipped in the second ("fox" → "gox").
  - From reading the code, not demonstrated: `AesDecrypt` returns its input when the padding check fails, and other
    text when it passes. A party who can submit modified payloads to a consumer's decryption and see which of the two
    came back has a CBC padding oracle on every block after the first (the IV is also the key's salt, so a changed IV
    changes the key). Each query costs one PBKDF2 run, which slows the attack, not stops it.
  - A wrong password is not always detected: in 300 of 80,000 tries (about 0.4 %) it left valid padding, and
    `AesDecrypt` returned other text as a success. Since 2026-11-15 (A5) the README says so, and its "Security notes"
    describe the missing integrity protection.
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
  four in `C:\ProgramData\Microsoft\Crypto\Keys` (the folder held 7,329 files before it). Since 2026-11-15 (A5) the
  README says that the keys stay there, and how to delete one. Question: is the
  persistence intended for the two loaders as well? Options: an optional `X509KeyStorageFlags` parameter on the loaders,
  defaulting to the current flags (no behaviour change); or ephemeral keys by default (a breaking change). The tests
  no longer leave keys behind: since 2026-11-15 `CertificateFactoryTests` deletes them after each test (A4).
- **The PBKDF2 default:** 100,000 iterations of HMAC-SHA-256. For comparison, OWASP's Password Storage Cheat Sheet gives
  600,000 for PBKDF2-HMAC-SHA256 (not checked in this session). The count is not in the payload, and the default is
  compiled into the callers, so a new default needs the format marker of the first item. Question: keep 100,000?
- **`GetForLocalhost` fails in a time zone west of UTC.** `NotAfter` is `DateTime.MaxValue`, which has no UTC kind, so
  `new DateTimeOffset(endTime)` applies the local offset; with a negative offset the UTC time passes year 9999 and the
  constructor throws. Verified on Linux (2026-11-11): with `TZ=America/New_York` the call returns an `Unexpected` error
  and `GetForLocalhostTest` fails; with `TZ=UTC` both pass. A fix also moves `NotAfter` on machines east of UTC by their
  offset (today it is 9999-12-31 22:59:59Z at UTC+01:00), so it needs a decision. Since 2026-11-15 (A5) the README
  warns, and names the work-around: `CreateSelfSigned` with `DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc)`
  (verified at -05:00, UTC and +01:00).
- **The local 3.0.0 package; the published versions.** `artifacts/Forge.Next.Security.3.0.0.nupkg` (built 2026-06-30
  20:01, between the 3.0.0 and the 3.1.0 commits) holds an intermediate build: its DLL returns `ErrorOr` and references
  `Forge.Next.Shared` 3.0.0, while its README documents the throwing API of the 3.0.0 commit. Which versions are
  published is not known here: the local NuGet cache has none, and nuget.org was not asked. Do not publish the local
  3.0.0 file.

## Not verified yet

- **The `net8.0`, `net9.0` and `net11.0` builds** are tested on Windows only (since 2026-11-15); the Linux run of
  2026-11-11 tested `net10.0`.
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
- **The `net8.0` PFX loading** also accepts a DER certificate (the probe loaded a `.cer` with `GetFromFile`); the other
  targets do not. Whether the difference should stay. Since 2026-11-15 the tests pin each target's result, so a change
  shows up as a failing test.
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
