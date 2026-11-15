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
