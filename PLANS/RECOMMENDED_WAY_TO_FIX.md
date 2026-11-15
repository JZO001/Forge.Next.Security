# Recommended way to fix the open findings

Written on 2026-11-12 by a Claude Code session for the Claude Code session that fixes these items here, locally, with
Zoltán. It turns the findings of `AI/OPEN.md` (found and verified on 2026-11-11, see `AI/VERIFICATION.md`) into an order
of work. Read `CLAUDE.md` and `AI/` first. The invariants of `CLAUDE.md` still hold; an item that changes one says so,
and needs Zoltán's decision.

## How to work through it

- One item at a time, in the order below. After an item, report and stop until Zoltán names the next one.
- An item marked **Decision** needs Zoltán's answer before any code: ask with the options and the recommendation given
  here, one question at a time. Check the facts again first: line numbers move, member names rarely do.
- Every change: a 0-warning build of all targets, all tests, and for a package change the package check of
  `AI/VERIFICATION.md`, always with `-p:PackageOutputPath=<a folder outside the repository>\`, so `artifacts/` stays
  as it is.
- In the same step: a public change into `README.md`, a decision into `AI/HISTORY.md`, a check into
  `AI/VERIFICATION.md`; a closed item leaves `AI/OPEN.md`, and its box here gets ticked with the date.
- No git command that writes unless Zoltán asks (`/commit.changes`). No name of a product or project that uses this
  package (`CLAUDE.md`).

## Releases

- **Release A**, without a change of behaviour or of a signature (a patch): A1 to A5. It also carries what Zoltán
  added on 2026-11-15: the `net11.0` target and Forge.Next.Shared 3.3.2. Done on 2026-11-15 as 3.2.1 (with B6),
  committed before Release B.
- **Release B**, new API and changed behaviour (at least a minor): B1 to B6.

Zoltán decides whether they ship apart. Before the first Release build of a release, ask which version is next and raise
`AssemblyVersion`: `artifacts/` holds 3.2.0, and a Release build of the current version overwrites it. Never publish
`artifacts/Forge.Next.Security.3.0.0.nupkg`: it is an intermediate build whose README does not match its DLL.

## Release A

### A1. One XML documentation file per target [x] 2026-11-15

- **Problem:** `<DocumentationFile>Forge.Next.Security.xml</DocumentationFile>` makes the target builds (four since
  2026-11-15), which run in parallel, write one file in the project folder, and each target copies whatever is there
  into its output. The packages so far are whole only because the targets document the same members; in Forge.Next.Formatters and
  Forge.Next.Shared the same setting shipped empty, truncated and other targets' files.
- **Fix:** in `Forge.Next.Security/Forge.Next.Security.csproj` remove the `DocumentationFile` line (keep
  `GenerateDocumentationFile`) and the `<None Remove="Forge.Next.Security.xml" />` item; remove
  `**/Forge.Next.Security.xml` from `.gitignore`, and delete the ignored `Forge.Next.Security/Forge.Next.Security.xml`.
  Each target then writes its own file under `obj/<configuration>/<target>/`.
- **Check:** a Release build into a temporary folder, twice; every `lib/<target>/Forge.Next.Security.xml` in the
  `.nupkg` parses as XML and holds its target's members.

### A2. The license in the package [x] 2026-11-15

- **Problem:** `<licenses>` is not an MSBuild or NuGet property, so no package has a license element.
- **Fix:** replace it with `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, as Forge.Next.Shared and
  Forge.Next.LocalWebShell have.
- **Check:** the package's `.nuspec` has `<license type="expression">Apache-2.0</license>`, and the build no NU5xxx
  warning.

### A3. Known-answer tests for the AES payload [x] 2026-11-15

- **Why before B1:** B1 adds a format beside the current one. A fixed payload pins the current one, so no later change
  makes stored data undecryptable without a failing test; `AesDecrypt` would hide it by returning its input.
- **Fix:** in `tests/Forge.Next.Security.Tests/AesCryptographyTests.cs`, constants made once with today's code: a
  payload of `AesEncrypt` with the defaults, its password and plaintext, and `AesDecrypt` must give the plaintext back.
  One more with an explicit `iterations` and `HashAlgorithmName.SHA512`, which pins that the parameters are not in the
  payload and must be passed again.

### A4. Tests on every target [x] 2026-11-15

- **Problem:** the test project targets `net10.0` only, so the `#if NET8_0` branch of `GetFromRawData` and `GetFromFile`
  never runs.
- **Fix:** `<TargetFrameworks>net8.0;net9.0;net10.0;net11.0</TargetFrameworks>` in the test project (`net11.0` since
  2026-11-15). `GetFromFile` on a `.cer` loads on `net8.0` (the constructor reads DER) and fails on the later targets:
  assert each target's own result, and write the difference into `AI/DESIGN.md`.
- **Found on 2026-11-15:** no test loads a `.cer` yet, so the difference needs new tests (`GetFromFile_CerFile_Test`,
  and the same for `GetFromRawData` with DER bytes), with `#if NET8_0` in the test. The `net9.0` and `net11.0` results
  are not measured yet; the tests will show them.
- **Side effect:** a run loads PFX data four times per target, so a run on four targets leaves about 16 key files in
  the machine key store until B4. A possible interim fix without an API change: the tests delete the key after each PFX
  load (`RSACng.Key.Delete()` on Windows). Try it before relying on it.
- **Check:** all tests pass on all four targets.

### A5. The README tells the truth [x] 2026-11-15

Correct the README to the code as it is (the list in `AI/OPEN.md`):
- `AesDecrypt` with a wrong password returns the input unchanged in about 99.6 % of the cases; otherwise other text
  comes back as a success, because the payload has no integrity check (B1);
- the skip rules do not skip `0.0.0.0` and `::`, and the default entries hold `0.0.0.0` twice;
- `GetAlternateNames`: a custom DNS name comes first among the DNS entries;
- `AesCryptography.Iterations` and `AesCryptography.DefaultOutputLength` are documented;
- the loaded keys stay in the machine key store (B4), and `GetForLocalhost` fails in a time zone west of UTC (B5);
- a short "Security notes" section: no integrity protection in the AES payload, the legacy protection of the PFX
  export (B3), and that every `Unexpected` error carries the exception's stack trace in its metadata (B6), so a caller
  that sends an error out of its process strips it.

## Release B

### B1. An authenticated AES payload [ ] (Decided 2026-11-15: (a), the format and the refinements below)

- **Problem:** `AesEncrypt` is AES-CBC without a MAC. One flipped ciphertext bit decrypted to altered text as a success
  ("fox" became "gox"); a wrong password was missed in 300 of 80,000 tries; and since `AesDecrypt` answers differently
  for a bad padding and a good one, a party who can submit changed payloads and see the answer has a padding oracle
  (from reading the code, not demonstrated).
- **Decision, the API:**
  - (a) new methods, e.g. `AesGcmEncrypt` and `AesGcmDecrypt`, write and read the new format. `AesDecrypt` reads both
    formats and keeps its contract (the input back on any failure). `AesEncrypt` keeps writing the current format and
    gets `[Obsolete]` with a pointer to the new method. **Recommended:** nothing changes for the current callers, and
    an older package version still reads what `AesEncrypt` writes.
  - (b) `AesEncrypt` writes the new format. An older package version cannot read it: breaking for anyone who decrypts
    with an older version, so a major version.
- **Format proposal** (confirm with Zoltán):
  `v2:<iterations>:<Base64 salt>:<Base64 nonce>:<Base64 ciphertext followed by the tag>`.
  - Key: PBKDF2-HMAC-SHA256 (`Rfc2898DeriveBytes.Pbkdf2`) of the UTF-8 password with a random 16-byte salt, 32 bytes.
  - Cipher: AES-256-GCM (`new AesGcm(key, 16)`), a random 12-byte nonce, a 16-byte tag, and as associated data the
    UTF-8 text before the ciphertext, so the version, the iterations, the salt and the nonce are authenticated too.
  - Telling the formats apart: test for the prefix `v2:`, the colon included, never for `v2` alone. A current payload
    starts with a 24-character Base64 IV, which starts with `v2` about once in 4,096 payloads (`v` and `2` are Base64
    characters), but never holds a `:` (found on 2026-11-15).
  - Where `AesGcm.IsSupported` is false, return an error; never fall back to the old format.
- **Refinements** (found and decided on 2026-11-15):
  - The decrypt checks the iteration count of the payload before it runs PBKDF2: below 1 or above an upper bound
    (proposed: ten times the default, 6,000,000) is a malformed payload. Without the bound, a party who can submit
    payloads can make every decrypt run up to 2,147,483,647 iterations: the tag is checked only after the key exists.
  - The new methods take `int? iterations = null`, and the library fills in its default at run time, so a later raise
    reaches the callers without a recompile (`CLAUDE.md` invariant 1); a public constant for it would be compiled in
    again. A value below 1 is a `Validation` error with the parameter's name.
  - The new encrypt encrypts any non-null content exactly, empty and whitespace-only included, so the decrypt gives it
    back; `AesEncrypt` keeps turning such content into `""`.
  - `[Obsolete]` on `AesEncrypt` raises CS0618 wherever it is called: the tests of the current format suppress it with
    `#pragma warning disable CS0618` around the calls (the build stays at 0 warnings), and the README warns that a
    caller who treats warnings as errors gets a build error until it moves to the new method or suppresses the warning.
- **Errors of the new decrypt:** an error, not the input. A malformed payload (format, Base64, lengths, the iteration
  count) is a `Validation` error; a failed authentication (a wrong password or a changed payload) is a `Failure`. Each
  has a code of its own (proposed: `AesGcm.InvalidPayload` and `AesGcm.AuthenticationFailed`; show the names to Zoltán
  when coding). No password, key, salt or plaintext in an error or its metadata (invariant 7).
- **Tests:** the round trip; one flipped bit in each part (version, iterations, salt, nonce, ciphertext, tag) gives the
  authentication error and never text; a wrong password 20,000 times (with `iterations: 1`) never gives text; a
  known-answer payload of the new format; the A3 payloads still decrypt with `AesDecrypt`.
- **Docs:** README (the new methods, the format, the migration: read old, write new), `CLAUDE.md` invariant 4 (the new
  methods' errors) and invariant 5 (two formats, both readable), `AI/DESIGN.md`, `AI/HISTORY.md`.

### B2. The PBKDF2 iterations of the new format [ ] (Decided 2026-11-15: 600,000, after the check below)

- The new format records its iterations, so a later default can grow without breaking anything.
- **Recommended:** 600,000, the figure the OWASP Password Storage Cheat Sheet gave for PBKDF2-HMAC-SHA256. Check the
  current figure before deciding, and measure one decrypt on the slowest machine Zoltán names: every decrypt runs it.
- The constant `Iterations` (100,000) stays, as the current format's default: it is compiled into the callers.
- The new default is applied at run time (`int? iterations = null`, see B1), not as a new public constant.
- Should the check show a different current figure, or the measurement an unbearable decrypt, go back to Zoltán.

### B3. The PFX export's protection [ ] (Decided 2026-11-15: AES on `net10.0` and later, today's export on `net8.0` and `net9.0`)

- **Problem:** `ExportToPfxRawData` writes TripleDES and SHA-1 with 2,000 iterations (OpenSSL, 2026-11-11), cheap to
  attack offline with a weak password, while the README suggests keeping a PFX as a backup.
- **Options:**
  - on `net10.0`, `certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password)`, behind
    `#if NET10_0_OR_GREATER` (the reference packs of `net8.0` and `net9.0` have no `ExportPkcs12`);
  - on `net8.0` and `net9.0`, (a) keep today's export and document the difference (**recommended**), or (b)
    `Pkcs12Builder` from `System.Security.Cryptography.Pkcs`, which is a new package: only on Zoltán's word.
- Before coding, check that every system that imports these files reads an AES-protected PKCS#12; old Windows versions
  are said to read only the TripleDES form. If one does not, go back to Zoltán.
- `ExportPkcs12` and `Pkcs12ExportPbeParameters` are in the `net10.0` and `net11.0` reference packs, not in `net9.0`'s
  (checked 2026-11-15), so `#if NET10_0_OR_GREATER` covers `net11.0` too. It is a second per-target branch:
  `CLAUDE.md` invariant 3 changes with it.
- **Check:** `openssl pkcs12 -in <file> -info -noout` on an export of each target.

### B4. The keys left in the machine key store [ ] (Decided 2026-11-15: the optional parameter, today's flags as its default)

- **Problem:** the password overload of `CreateSelfSigned`, `GetFromRawData` and `GetFromFile` load with
  `Exportable | PersistKeySet | MachineKeySet`, and nothing removes the key file; one test run left four in
  `C:\ProgramData\Microsoft\Crypto\Keys`.
- **Recommended:** an optional `X509KeyStorageFlags` parameter on the three methods, whose default is today's flags: no
  behaviour change, but a signature change, so a minor version. Keep the persisted default: verify first that a TLS server
  on Windows needs a persisted key (SChannel and ephemeral keys), which is the likely reason for it.
- **Docs:** the README says that the keys stay, and how to remove one.
- **Tests:** pass `X509KeyStorageFlags.EphemeralKeySet` where the platform has it, so a run leaves no key file; compare
  the folder's file count before and after a run. Since A4 the tests already delete the persisted keys
  (`CertificateFactoryTests.Dispose`); keep that for the tests of the default flags.

### B5. `GetForLocalhost` west of UTC [ ] (Decided 2026-11-15: accepted)

- **Problem:** `NotAfter` is `DateTime.MaxValue`, whose kind is not UTC, so `new DateTimeOffset(endTime)` applies the
  local offset. West of UTC the UTC time passes year 9999 and the call returns `Unexpected` (verified on Linux with
  `TZ=America/New_York`).
- **Fix:** `GetForLocalhost` passes `DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc)`. `CreateSelfSigned`
  converts both times through one internal helper that takes the time zone (`TimeZoneInfo.Local` in production) and
  clamps a time beyond the range, so a caller's local `DateTime.MaxValue` works too. Unit tests pass custom zones at
  -05:00 and +01:00 (`TimeZoneInfo.CreateCustomTimeZone`).
- **How the helper converts** (found on 2026-11-15): a UTC time keeps offset zero; any other time takes
  `zone.GetUtcOffset(time)`, its ticks minus the offset's ticks, clamped to the range of `DateTime`, as a UTC
  `DateTimeOffset`. Not `TimeZoneInfo.ConvertTimeToUtc`: it throws for a time the daylight-saving switch skips, while
  today's `new DateTimeOffset(time)` does not. So every time within the range converts as today.
- **Reading `NotAfter` back** (found on 2026-11-15, see `AI/VERIFICATION.md`): east of UTC a certificate that ends at
  9999-12-31 23:59:59Z cannot be shown in local time, so `X509Certificate2.NotAfter` returns the clamped
  `DateTime.MaxValue` (local), and `.ToUniversalTime()` of it gives 22:59:59Z at +01:00. The tests of the fix read the
  encoded `notAfter` from `RawData` (`System.Formats.Asn1`), not the property.
- **The decision:** `NotAfter` becomes 9999-12-31 23:59:59Z everywhere; today it is 22:59:59Z at +01:00, so east of UTC
  it moves later by the offset. **Recommended:** accept it.
- **Check:** the Linux run of `AI/VERIFICATION.md` with `TZ=America/New_York` and `TZ=UTC`.

### B6. Errors without the stack trace [x] 2026-11-15 (Decided 2026-11-15: (a), the README note of A5; no code, closed with A5)

- Forge.Next.Shared 3.3.2 (referenced since 2026-11-15) offers `includeStackTrace` on `Protect`; this package does not
  pass it.
- **Options:**
  - (a) the README note of A5 only;
  - (b) an optional `includeStackTrace` parameter on every public method, default `true` (today's behaviour), a
    signature change on every method.
- **Recommended:** (a), unless Zoltán knows a caller that sends these errors out of its process.

## Ideas, only when Zoltán asks

These are behaviour changes (C1) or clean-ups without one (the rest); `AI/OPEN.md` has the details.

- C1. The default SAN list adds `0.0.0.0` twice, and the skip rules do not skip `0.0.0.0` and `::`: remove the duplicate
  and skip both, which changes the certificate's content (README).
- C2. `FindByDnsNames` lower-cases the request once per certificate, so its work grows with the square of the store's
  size: lower-case it once before the loop. An empty request matches every certificate: document it.
- C3. Dispose the store's certificates that are not returned (`FindByThumbprint`, `FindByDnsNames`, `RemoveFromStore`),
  and the ephemeral certificate inside the password overload of `CreateSelfSigned`.
- C4. `OperatingSystem.IsWindows()` instead of `Environment.OSVersion.Platform`, so the CA1416 suppression can go.
- C5. `typeof(AesCryptography)` as the receiver of `Protect` in `AesCryptography`.
- C6. Rename `CertificateStore.cs` to `CertificateAccess.cs`, and its tests to `CertificateAccessTests`.
- C7. The XML documentation: the empty `<returns>`, the `<exception cref="ArgumentException">` on a method that returns
  errors, and `AesEncrypt`'s "a base64-encoded string" for `<Base64 IV>:<Base64 ciphertext>`.
- C8. A `net11.0` target, as Forge.Next.Shared 3.3.1 has. [x] 2026-11-15, by Zoltán, with Forge.Next.Shared 3.3.2
  (`AI/HISTORY.md`).
