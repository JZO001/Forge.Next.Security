# Open items

As of 2026-11-11; updated 2026-11-15 (`net11.0`, Forge.Next.Shared 3.3.2). Close an item by moving its outcome into `HISTORY.md` (decisions) or `VERIFICATION.md` (checks), and
deleting it here.

The order and the way to fix them: `PLANS/RECOMMENDED_WAY_TO_FIX.md` (2026-11-12).

## Waiting for Zoltán

The security findings of 2026-11-11 (the AES format, the PBKDF2 default, the PFX export, the key storage flags,
`GetForLocalhost`, the stack traces) were decided and fixed on 2026-11-15 (`PLANS/RECOMMENDED_WAY_TO_FIX.md`, A1 to B6;
`HISTORY.md`). What is left here waits for Zoltán.

- **The local 3.0.0 package; the published versions.** `artifacts/Forge.Next.Security.3.0.0.nupkg` (built 2026-06-30
  20:01, between the 3.0.0 and the 3.1.0 commits) holds an intermediate build: its DLL returns `ErrorOr` and references
  `Forge.Next.Shared` 3.0.0, while its README documents the throwing API of the 3.0.0 commit. Which versions are
  published is not known here: the local NuGet cache has none, and nuget.org was not asked. Do not publish the local
  3.0.0 file.

## Not verified yet

- **The `net8.0` and `net9.0` builds** are tested on Windows only (since 2026-11-15); on Linux, the run of 2026-11-11
  tested `net10.0`, the runs of 2026-11-15 `net11.0` (the `sdk:11.0` image has no other runtime).
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
  so ("nothing to encrypt"). `AesGcmEncrypt` (B1) encrypts it and gives it back exactly.
- **The platform guard:** `OperatingSystem.IsWindows()` instead of `Environment.OSVersion.Platform`, so the CA1416
  suppression can go.
- **`typeof(CertificateFactory)`** is the receiver of `Protect` in `AesCryptography`; `typeof(AesCryptography)` would
  read better. No behaviour depends on it.
- **The file name** `CertificateStore.cs` holds `CertificateAccess`, and its tests are `CertificateStoreTests`.
- **The XML documentation is thin:** empty `<returns>` elements, an `<exception cref="ArgumentException">` on a
  `CreateSelfSigned` overload that returns errors, and `AesEncrypt`'s "a base64-encoded string" for what is
  `<Base64 IV>:<Base64 ciphertext>`.
- **The PFX export's iteration count:** both forms of `ExportToPfxRawData` stretch the password with 2,000 iterations
  (the presets of `ExportPkcs12` and `Export`). On `net10.0` and later,
  `ExportPkcs12(new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, <count>), password)`
  would take a higher count; whether importers (Windows, older .NET loaders and their limits) accept it is not
  checked. A behaviour change: version and README.
- **The `.nuspec`'s repository commit** names the commit before the release: the 3.1.0 package (built 2026-06-30
  20:33, the commit 20:34) names `e70ca0e4`, the 3.2.0 package (built 2026-11-02 15:29, the commit 15:30) names
  `3aaaea0d`: each was built just before its release commit.
