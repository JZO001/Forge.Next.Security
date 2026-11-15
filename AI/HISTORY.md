# History and decisions

Newest last. Each entry: what was asked or decided, by whom, and why. The entries before 2026-11-11 are reconstructed
from the commit messages and diffs; where they give no reason, the entry says only what changed.

## 2026-06-30 – The repository

The first commit holds the `.gitignore` and the `LICENSE` (Apache License 2.0).

## 2026-06-30 – 3.0.0: the certificate helpers

The first implementation, multi-targeting `net8.0`, `net9.0` and `net10.0`, without package dependencies:
- `CertificateFactory`: self-signed certificates (RSA 2048, SHA-256 with PKCS#1, the TLS server authentication EKU, not
  a CA) with the Subject Alternative Name rules (the caller's entries, the default entries, the reserved and loopback
  entries skipped); a password overload that round-trips the certificate through a PFX and loads it with
  `MachineKeySet`; PFX and CER export; PFX loading from bytes or a file (the constructor on `net8.0`,
  `X509CertificateLoader` on the others); `GetForLocalhost`;
- `CertificateAccess` (in `CertificateStore.cs`): add, find by thumbprint (`null` when absent), list, find by DNS names,
  read the SAN entries, remove;
- the methods returned values or `null`, and let exceptions through;
- the test project (`net10.0`, xUnit, Shouldly, NSubstitute), the README as a full API reference; the prompts asking
  for the README and the tests are in `prompts/`; the `crt.commit.msg` command writes a commit message into
  `<branch>.txt`.

Two generated XML documentation files were committed with it.

## 2026-06-30 – 3.1.0: `ErrorOr` results; AES encryption

From the commit message:
- every public method returns `ErrorOr<T>` (`ErrorOr<Success>` for `AddToStore` and `RemoveFromStore`); the work runs
  in the `Protect` helper of Forge.Next.Shared, which turns exceptions into `Unexpected` errors, so a wrong PFX password
  or a missing file became a returned error; `FindByThumbprint` returns `NotFound` instead of `null`;
- both `CreateSelfSigned` overloads and `GetForLocalhost` take `keySize` (default 2048, the size 3.0.0 used);
- `AesCryptography` is new: PBKDF2 key derivation (`MakeAESKey`), AES-CBC encryption and decryption (`AesEncrypt`,
  `AesDecrypt`) with an `iv:ciphertext` payload; the hash algorithm, the key length and the iteration count are
  parameters; a null password or salt is a `Validation` error; `AesDecrypt` maps every other failure back to its input
  "so a wrong password never discloses the plaintext";
- the `Forge.Next.Shared` 3.0.0 package reference (it brings `ErrorOr` and `Protect`);
- the tests rewritten for the `ErrorOr` API, `AesCryptographyTests` added; the README rewritten.

Every return type changed: a breaking change, released as a minor version. `main.txt`, holding the text of this commit
message, was committed with it and deleted in the next commit.

## 2026-07-01 – The generated XML files out of the repository

Both XML documentation files were deleted, and `.gitignore` ignores `**/Forge.Next.Security.xml`.

## 2026-11-02 – 3.2.0: Forge.Next.Shared 3.3.0

`AssemblyVersion` 3.1.0.0 → 3.2.0.0, and the `Forge.Next.Shared` reference 3.0.0 → 3.3.0. No source change. The test
project's packages were raised as well (`Microsoft.NET.Test.Sdk` 18.11.0, `NSubstitute` 6.2.0,
`xunit.runner.visualstudio` 4.0.1). The commit message ("v3.2.0") gives no reason.

## 2026-11-11 – The package icon: the Forge mark

Zoltán chose a new icon for the Forge packages: the Forge mark, a hexagon with a smaller, filled hexagon inside, the two
joined by three lines, on a dark rounded tile, so it reads on a light and on a dark ground. `logo.png` in this
repository was replaced on 2026-11-11 with this mark, 128 by 128 pixels (NuGet's advice), the same file as in
Forge.Next.Shared, in place of the earlier logo, which looked much like the Jedi Order's emblem (Lucasfilm), a trademark
risk. The change was committed on 2026-11-15, with the knowledge base. The project packs `logo.png` as before. The packages built so far (3.0.0 to 3.2.0
in `artifacts/`) carry the old icon; the next version carries the new one.

## 2026-11-11 – The knowledge base

Zoltán asked for a knowledge base like the ones in the Forge.Next.Shared and Forge.Next.LocalWebShell repositories;
`CLAUDE.md` and this folder are it. `CLAUDE.md` also describes the `/commit.changes` command, which was already in the
repository folder, untracked (`.claude/commands/commit.changes.md`, the same file as in Forge.Next.Shared).

**Checked while it was made** (see `VERIFICATION.md`, 2026-11-11): the build, the tests, the package contents, the
local packages in `artifacts/`, a Linux run in Docker, and a probe of the README's statements against the built package.

**Found** (see `OPEN.md`):
- the AES payload has no integrity protection: a flipped ciphertext bit decrypts to altered text without an error; and
  a wrong password returns other text instead of the input in about 0.4 % of the cases;
- `ExportToPfxRawData` writes TripleDES and SHA-1 PKCS#12 with 2,000 iterations;
- every PFX load persists an exportable private key in the machine key store; a test run left four key files;
- the errors carry the exceptions' stack traces;
- `GetForLocalhost` fails in a time zone west of UTC;
- the package carries no license: the project file sets `<licenses>`, which NuGet does not know;
- the local `artifacts/Forge.Next.Security.3.0.0.nupkg` does not match the 3.0.0 commit;
- README statements that do not match the code.

## 2026-11-15 – `net11.0`; Forge.Next.Shared 3.3.2

Zoltán added the `net11.0` target (as Forge.Next.Shared 3.3.1 and Forge.Next.LocalWebShell 1.1.0 got on 2026-11-11) and
raised the `Forge.Next.Shared` reference 3.3.0 → 3.3.2. No source change: `NET8_0` is not defined for `net11.0`, so it
loads PFX data with `X509CertificateLoader`, as `net9.0` and `net10.0` do. Forge.Next.Shared 3.3.2 lists no
`Microsoft.Extensions.Logging.Abstractions` for `net11.0`, because the .NET 11 shared framework carries it (the
`Microsoft.NETCore.App` 11.0.0 folder holds the DLL). `AssemblyVersion` stays 3.2.0.0 until the next release; which
version that is, is asked before its Release build (`PLANS/RECOMMENDED_WAY_TO_FIX.md`, "Releases"). The README's target
list names `net11.0`. Checked: see `VERIFICATION.md`, 2026-11-15.

Zoltán had the knowledge base, the new icon and this change committed together, before the first item of the fix plan.

## 2026-11-15 – The decisions of the fix plan

Zoltán asked for a fix plan from `PLANS/RECOMMENDED_WAY_TO_FIX.md`. Checking the plan against the code found
refinements, now written into it: the new AES format is told apart by the prefix `v2:` (the IV of a current payload
starts with `v2` about once in 4,096); the new decrypt bounds the payload's iteration count before it runs PBKDF2; the new
methods take `int? iterations = null`, so the default is not compiled into the callers; the `GetForLocalhost` fix
converts with `GetUtcOffset`, not with `ConvertTimeToUtc`; and A4 needs new `.cer` tests.

Zoltán decided B1 to B6 as the plan recommends:
- B1: new methods (`AesGcmEncrypt`, `AesGcmDecrypt`) write and read a `v2:` format: AES-256-GCM, PBKDF2-HMAC-SHA256,
  the iterations, the salt and the nonce in the payload and authenticated. `AesDecrypt` reads both formats and keeps
  returning its input on a failure; `AesEncrypt` keeps the current format and gets `[Obsolete]`. The reason: nothing
  changes for the current callers, and an older package version still reads what `AesEncrypt` writes. The new decrypt
  returns errors: `Validation` for a malformed payload, `Failure` for a failed authentication. The new encrypt encrypts
  empty and whitespace-only content too.
- B2: 600,000 iterations for the new format, after checking OWASP's current figure and measuring a decrypt.
- B3: `ExportPkcs12` with PBES2, AES-256 and SHA-256 on `net10.0` and later; today's export on `net8.0` and `net9.0`,
  documented; after checking that the importers read the AES form.
- B4: an optional `X509KeyStorageFlags` parameter on the password overload of `CreateSelfSigned`, `GetFromRawData` and
  `GetFromFile`, today's flags as its default, after checking why the key is persisted.
- B5: `NotAfter` of `GetForLocalhost` becomes 9999-12-31 23:59:59Z everywhere; east of UTC it moves later by the offset.
- B6: a README note (A5), no `includeStackTrace` parameter.

None is coded yet. The order stays: Release A first. Which versions the releases get is asked before their Release
builds.

## 2026-11-15 – A1: one XML documentation file per target

Zoltán asked for A1 of the fix plan. `<DocumentationFile>Forge.Next.Security.xml</DocumentationFile>` made the target
builds, which run in parallel, write one file in the project folder, and each target copied whatever was there into its
output and so into the package. The packages so far were whole only because every target documents the same members;
the same setting put an empty, a truncated or another target's file into packages of Forge.Next.Formatters and
Forge.Next.Shared. Changed:
- the project file keeps `GenerateDocumentationFile` and drops the `DocumentationFile` line and the
  `<None Remove="Forge.Next.Security.xml" />` item, so each target writes its own file under
  `obj/<configuration>/<target>/`, as in Forge.Next.LocalWebShell;
- `.gitignore` drops the `**/Forge.Next.Security.xml` entry and the blank line before it, which the "gitignore update"
  commit (3aaaea0) had added, so it ends as in the first commit;
- the ignored `Forge.Next.Security/Forge.Next.Security.xml` is deleted.

No change to the package's API or behaviour. Checked: see `VERIFICATION.md`, 2026-11-15.

From here Zoltán asked for the plan's items to be worked through one after the other, stopping only for a technical
question.

## 2026-11-15 – A2: the license in the package

The project file set `<licenses>`, which neither MSBuild nor NuGet knows, so no package so far (3.0.0 to 3.2.0) carried a
license. It now sets `<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>`, as Forge.Next.Shared and
Forge.Next.LocalWebShell do; the `LICENSE` file is the Apache License 2.0. The package's `.nuspec` gets
`<license type="expression">Apache-2.0</license>` and NuGet's `licenseUrl`. Checked: see `VERIFICATION.md`, 2026-11-15.

## 2026-11-15 – A3: known-answer tests for the AES payload

Before B1 adds a second format, the current one is pinned: `AesCryptographyTests` holds two payloads made once with the
3.2.0 code (the defaults; SHA-512 with 5,000 iterations), and three tests: each decrypts to its plaintext with its own
parameters, and the SHA-512 payload with the defaults gives the input back, not the plaintext (the payload does not
record its parameters). A change to the format, the salt rule or a default now fails a test instead of passing silently
behind `AesDecrypt`'s fallback. The payloads must never be regenerated to make a test pass.

## 2026-11-15 – A4: tests on every target

The test project targets `net8.0`, `net9.0`, `net10.0` and `net11.0`, the library's targets, so the `#if NET8_0` branch
of the PFX loading runs in the tests:
- `ExportToCerFileTest` reloads the DER bytes with the constructor on `net8.0`, which has no `X509CertificateLoader`;
- `GetFromRawData_DerData_Test` and `GetFromFile_CerFile_Test` pin the targets' difference: DER data loads as a public
  certificate on `net8.0` and is an `Unexpected` error on the later targets (`net9.0` and `net11.0` measured for the
  first time, both as `net10.0`).

With four targets a run would have left 16 key files in the machine key store. The plan's interim fix, tried first and
kept: `CertificateFactoryTests` registers each successful PFX load (`DeleteKeyAfterTest`), and its `Dispose` deletes the
persisted CNG keys after each test (`RSACng.Key.Delete()` on Windows), so a run leaves none. No change to the library.

## 2026-11-15 – A5: the README tells the truth; B6 closed

The README now matches the code, with no change to the code:
- `AesDecrypt`: a wrong password usually returns the input, but in about 0.4 % of the cases other text as a success; the
  payload does not record its parameters; the lenient note says that comparing with the input catches most failures,
  not all;
- `AesCryptography`: the constants `Iterations` and `DefaultOutputLength`, and that they are compiled into the callers;
- the SAN section: `0.0.0.0` twice in the defaults, and `0.0.0.0` and `::` not skipped;
- `GetAlternateNames`: the custom entries come first among the DNS entries (the example output corrected);
- the persisted keys stay in the machine key store, and how to delete one (`RSACng.Key.Delete()`, the same call the
  tests use since A4);
- `GetForLocalhost` fails west of UTC; the work-around (`CreateSelfSigned` with a UTC `DateTime.MaxValue`) was run on
  Windows at +01:00 and on Linux at -05:00 and UTC before it went in;
- `net8.0` also loads DER data in `GetFromRawData` and `GetFromFile`; the `ExportToCerFile` example notes that
  `X509CertificateLoader` needs `net9.0`;
- a new "Security notes" section: no integrity protection in the AES payload (and the padding oracle it allows), the
  legacy PFX protection, the stack traces in the `Unexpected` errors' metadata, and that the package's own errors hold
  no secrets;
- the Testing section: every target, the elevation, the key clean-up.

With the stack-trace note in place, B6 is closed as decided: no `includeStackTrace` parameter.

## 2026-11-15 – 3.2.1: Release A

Zoltán chose 3.2.1 for Release A (A1 to A5, B6, with the `net11.0` target and Forge.Next.Shared 3.3.2): a patch, as no
API or behaviour changed, and Forge.Next.Shared added `net11.0` in a patch too (3.3.1). `AssemblyVersion` 3.2.0.0 →
3.2.1.0. Release A is committed before Release B starts; the Release build into `artifacts/` and the publishing are
Zoltán's.

## 2026-11-15 – B1 and B2: the authenticated AES format

As decided (see "The decisions of the fix plan"), `AesCryptography` gets two methods and a second payload format:
- `AesGcmEncrypt(password, content, int? iterations = null)` writes
  `v2:<iterations>:<Base64 salt>:<Base64 nonce>:<Base64 ciphertext and tag>`: PBKDF2-HMAC-SHA256 with a random 16-byte
  salt, AES-256-GCM with a random 12-byte nonce and a 16-byte tag, the text before the last colon as associated data.
  Empty and whitespace-only content is encrypted too.
- `AesGcmDecrypt(password, encryptedContent)` returns errors: `Validation` `AesGcm.InvalidPayload`, `Failure`
  `AesGcm.AuthenticationFailed`, and `Failure` `AesGcm.NotSupported` where the platform has no AES-GCM (a third code,
  beside the two the plan proposed). The iteration count of a payload must be 1 to 6,000,000, checked before PBKDF2.
- `AesDecrypt` hands a payload starting with `v2:` to `AesGcmDecrypt` and turns its errors into the unchanged input.
- `AesEncrypt` is `[Obsolete]`; the tests of the legacy format suppress CS0618 around their regions.

B2: OWASP's Password Storage Cheat Sheet, read on 2026-11-15, still gives 600,000 iterations for PBKDF2-HMAC-SHA256
(220,000 for SHA-512, 1,400,000 for SHA-1); the page shows no date. The default is the private constant
`GcmDefaultIterations`, applied at run time. One decrypt took 46 ms on the development machine; the plan's measurement
on the slowest machine waits for Zoltán to name one (`OPEN.md`).

The legacy format is unchanged, and its known-answer tests (A3) still pass. A new known-answer payload pins the
authenticated format; Node.js decrypted it independently. Release B is a minor version (new API, an `[Obsolete]`);
its number is asked before its Release build.

## 2026-11-15 – B4: the key storage flags

The plan asked first why the PFX loads persist the key. A loopback `SslStream` probe on Windows answered it: SChannel
fails a TLS server handshake with an ephemeral key ("No credentials are available in the security package") and
completes it with a persisted one. So the default stays, and the password overload of `CreateSelfSigned`,
`GetFromRawData` and `GetFromFile` get an optional last parameter, `X509KeyStorageFlags keyStorageFlags`, whose default
is today's `Exportable | PersistKeySet | MachineKeySet` (the private constant `PfxKeyStorageFlags`, used by both
`#if NET8_0` branches). `EphemeralKeySet` loads the key into memory only. No behaviour change for a caller that passes
nothing; but the three signatures changed, so a caller compiled against an earlier version must be recompiled (the
old method no longer exists in the assembly): a minor version, as for `keySize` in 3.1.0. The README documents the
parameter, why the default persists, and the ephemeral option; tests pin the persisted default (Windows) and the
ephemeral loads of all three methods.

## 2026-11-15 – B5: `GetForLocalhost` in every time zone

As decided: `GetForLocalhost` passes `DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc)`, so its certificate
ends at 9999-12-31 23:59:59Z everywhere; east of UTC that is later than before by the offset (22:59:59Z at +01:00),
west of UTC the call no longer fails. `CreateSelfSigned` converts both times through the internal
`ToUtcDateTimeOffset(time, zone)`, which computes as `new DateTimeOffset(time)` did but clamps a result beyond
`DateTime`'s range, so a caller's local `DateTime.MaxValue` west of UTC (or `DateTime.MinValue` east of it) gives a
certificate instead of an `Unexpected` error: a behaviour change from error to success. The library's project file got
`InternalsVisibleTo` for the test assembly, so the tests pass custom zones (-05:00, +01:00). The README's work-around
note is replaced by the new behaviour and a note on reading `NotAfter` east of UTC.

## 2026-11-15 – B3: the PFX export; B2's measurement

Before B3, the plan asked whether every system that imports these PFX files reads the AES form. Zoltán: every importer
is modern. So `ExportToPfxRawData` exports, on `net10.0` and later, with
`ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password)` (PBES2, AES-256-CBC, HMAC-SHA-256, a SHA-256
MAC), behind `#if NET10_0_OR_GREATER`, a second per-target branch (`CLAUDE.md` invariant 3); `net8.0` and `net9.0`
keep the TripleDES export. The password overload of `CreateSelfSigned` round-trips through it, so its intermediate PFX
changes too, without a visible effect. A behaviour change for a caller on `net10.0` or later: an importer that reads
only TripleDES can no longer read the export (README). Both forms keep 2,000 iterations; a higher count is an idea in
`OPEN.md`, not decided.

On B2, Zoltán decided that no measurement on a slower machine is needed: 600,000 stays.

## 2026-11-15 – 3.3.0: Release B

Zoltán chose 3.3.0 for Release B (B1 to B5), committed after B3: a minor version, for the new API (`AesGcmEncrypt`,
`AesGcmDecrypt`), the `[Obsolete]` on `AesEncrypt`, the changed signatures of the three PFX loads (a recompile is
needed), and the changed behaviour (the PFX export on `net10.0` and later, `GetForLocalhost`'s `NotAfter`, the clamped
validity times). `AssemblyVersion` 3.2.1.0 → 3.3.0.0. The Release build into `artifacts/` and the publishing are
Zoltán's.
