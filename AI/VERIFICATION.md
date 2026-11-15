# Verification

## The checks

Pass `-p:PackageOutputPath=<a folder outside the repository>\` to every `dotnet build` and `dotnet test` of a check,
so a Release build cannot overwrite the packages in `artifacts/`.

| Check | How | What it proves |
| --- | --- | --- |
| Build | `dotnet build Forge.Next.Security.slnx -c Debug --no-incremental` | 0 warnings for every target (`net8.0`, `net9.0`, `net10.0`, `net11.0`). Needs the .NET 11 SDK or later (`net11.0` since 2026-11-15). |
| Tests | `dotnet test tests/Forge.Next.Security.Tests` | 59 tests (20 `AesCryptography`, 27 `CertificateFactory`, 12 `CertificateAccess`), against the `net10.0` build of the library. They add certificates to `CurrentUser\My` and remove them, and import PFX data into the machine key store. |
| Package contents | `dotnet build Forge.Next.Security/Forge.Next.Security.csproj -c Release`, then open the `.nupkg` as a zip | `lib/<target>/` with the DLL and the XML documentation for every target, the README and the icon; the `.nuspec` dependency groups match the table in `CLAUDE.md` |
| `artifacts/` untouched | SHA-256 of `artifacts/*.nupkg` before and after the checks | `artifacts/` is ignored by git, so `git status` cannot show a change there |
| Linux | Docker, `mcr.microsoft.com/dotnet/sdk:10.0`: the repository mounted read-only and copied into the container without `.git`, `.vs`, `bin`, `obj` and `artifacts`, then `dotnet test` with `TZ=UTC` and with `TZ=America/New_York` | The tests on Linux, and the time-zone dependence of `GetForLocalhost`. Needs Docker with a Linux engine and network for the restore. Since `net11.0` (2026-11-15) the library needs the .NET 11 SDK; the run with the `sdk:10.0` image predates it, and the `sdk:11.0` image is not tried yet. |
| Probe | A temporary console project outside the repository that references `lib/<target>/Forge.Next.Security.dll` of the built package and the `Forge.Next.Shared` version the package references; run on `net8.0` and `net10.0` | The README's statements against the package: a wrong password in 20,000 tries (`iterations: 1`), the SAN order and duplicates, an `outputLength` of 20, the metadata of an `Unexpected` error, a flipped ciphertext bit, `GetFromFile` on a `.cer`, `GetForLocalhost` |
| PFX encryption | `openssl pkcs12 -in <file> -info -noout -passin pass:<password>` on a PFX from `ExportToPfxRawData` | The algorithms and iteration counts of the export |

## What was run

| Date | Check | Where | Result |
| --- | --- | --- | --- |
| 2026-11-11 | Build | Windows 11 Pro 10.0.26300, SDK 11.0.100 (`dotnet --version`), elevated | 0 warnings, 0 errors, all three targets |
| 2026-11-11 | Tests | Windows 11, runtime 10.0.15, elevated, time zone UTC+01:00 | 59/59. The run created 4 files in `C:\ProgramData\Microsoft\Crypto\Keys`, one per successful PFX load in the tests, and left them there; `CurrentUser\My` kept no test certificate. |
| 2026-11-11 | Package contents, and the new icon: Release build with `PackageOutputPath` in a temporary folder | Windows 11, SDK 11.0.100 | 0 warnings. `Forge.Next.Security.3.2.0.nupkg`: `lib/net8.0`, `lib/net9.0`, `lib/net10.0` (DLL and XML), the README identical to the repository's, `logo.png` the new 128 × 128 mark (the same file as Forge.Next.Shared's), named as the icon in the `.nuspec`; one dependency group per target, each `Forge.Next.Shared` 3.3.0. The `.nuspec` has no license element. |
| 2026-11-11 | `artifacts/` untouched | Windows 11 | The SHA-256 and the time stamps of the three packages are unchanged; `git status` unchanged (`M logo.png`, `?? .claude/commands/commit.changes.md`) |
| 2026-11-11 | The local packages in `artifacts/` (read only: entries, `.nuspec`, the assembly references and types of the `net10.0` DLL) | Windows 11 | 3.1.0 and 3.2.0 match their commits. 3.0.0 does not: its DLL already returns `ErrorOr` and references `Forge.Next.Shared` 3.0.0 (no `AesCryptography`), while its README is the 3.0.0 commit's (see `OPEN.md`). None of the three has a license element. |
| 2026-11-11 | Linux | Docker, `mcr.microsoft.com/dotnet/sdk:10.0` (Ubuntu 24.04.5, SDK 10.0.401, runtime 10.0.12), as root | `TZ=UTC`: 59/59. `TZ=America/New_York`: 58/59, `GetForLocalhostTest` fails |
| 2026-11-11 | Probe | Windows 11, runtimes 10.0.15 and 8.0.34; and in the Linux container on 10.0.12 | A wrong password returned other text than the input in 91, 70, 72 and 67 of 20,000 tries (0.46 %, 0.35 %, 0.36 %, 0.34 %), the plaintext in none. The default SAN entries hold `0.0.0.0` twice; with `0.0.0.0` and `::` passed, three and two times. `outputLength` 20: `AesEncrypt` gives `Unexpected`, `AesDecrypt` the input. A missing file: `Unexpected`, metadata `type`, `message`, `stackTrace`. One flipped bit in the first ciphertext block of a three-block text: success, and "fox" became "gox" in the second block. `GetFromFile` on a `.cer`: loaded on `net8.0` (no private key), "ASN1 corrupted data" on `net10.0`. `GetForLocalhost`: an `Unexpected` error at -05:00 in the container ("The UTC time represented when the offset is applied must be between year 0 and 10,000."), success at UTC (`NotAfter` 9999-12-31 23:59:59Z) and on Windows at +01:00 (`NotAfter` 9999-12-31 22:59:59Z). The Windows runs left no file in the machine key store. |
| 2026-11-11 | PFX encryption | OpenSSL 3.5.9 in the development machine's Bash, PFX files exported on Windows by the `net8.0` and the `net10.0` build | Both: MAC SHA-1, 2,000 iterations; the shrouded key bag and the encrypted certificate data `pbeWithSHA1And3-KeyTripleDES-CBC`, 2,000 iterations |
| 2026-11-11 | The XML documentation in the local packages (read only: each `lib/<target>/Forge.Next.Security.xml` parsed, its members counted, its SHA-256 compared) | Windows 11 | 3.0.0, 3.1.0 and 3.2.0: every file whole, and the same file for every target (16, 22 and 22 members); see `OPEN.md` for why this is luck |
| 2026-11-15 | Build, after `net11.0` and Forge.Next.Shared 3.3.2 | Windows 11, SDK 11.0.100, elevated | 0 warnings, 0 errors, all four targets; `obj/project.assets.json` resolves `Forge.Next.Shared` 3.3.2 |
| 2026-11-15 | Tests | Windows 11, runtime 10.0.15, elevated | 59/59 (`net10.0`). `C:\ProgramData\Microsoft\Crypto\Keys`: 7,477 files before, 7,481 after, again 4 left behind |
| 2026-11-15 | Package contents: Release build with `PackageOutputPath` in a temporary folder | Windows 11, SDK 11.0.100 | 0 warnings. `Forge.Next.Security.3.2.0.nupkg` (still `AssemblyVersion` 3.2.0.0): `lib/net8.0`, `lib/net9.0`, `lib/net10.0`, `lib/net11.0` (DLL and XML); one dependency group per target, each `Forge.Next.Shared` 3.3.2, matching `CLAUDE.md`; the README and `logo.png` identical to the repository's (the README before its `net11.0` line); no license element. The four XML files parse, hold 22 members each, and are the same file. |
| 2026-11-15 | `artifacts/` untouched | Windows 11 | The SHA-256 of the three packages is unchanged |
| 2026-11-15 | The reference packs (read only) | Windows 11, `Microsoft.NETCore.App.Ref` 9.0.23, 10.0.15, 11.0.0 | `AesGcm` in all three; `ExportPkcs12` and `Pkcs12ExportPbeParameters` in 10.0.15 and 11.0.0, not in 9.0.23 |

## Not verified yet

See `OPEN.md`. In short:
- the `net8.0`, `net9.0` and `net11.0` builds are compiled but not tested; the probe touched the `net8.0` build only in
  part;
- a non-elevated Windows run (the PFX loads with `MachineKeySet`, which the README says usually need administrator
  rights);
- Linux as a non-root user, and macOS;
- which versions are published.
