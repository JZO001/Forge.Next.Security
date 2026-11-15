# Forge.Next.Security – notes for AI sessions working on this repository

This repository holds one NuGet package: a small library for X.509 certificates (self-signed certificates with
automatic Subject Alternative Names, PFX and CER export and import, certificate-store access) and for password-based AES
encryption (PBKDF2 key derivation, AES-CBC). Every public method returns an `ErrorOr` result. Read in this order:

1. `README.md`: the user documentation: every public type and method, with examples. It is packed into the NuGet
   package.
2. This file: the rules that must hold in every change.
3. `AI/README.md`: the knowledge base: how the package came about and what was decided (`AI/HISTORY.md`), the design
   (`AI/DESIGN.md`), how it is verified (`AI/VERIFICATION.md`), and what is still open (`AI/OPEN.md`).
4. `PLANS/RECOMMENDED_WAY_TO_FIX.md`: the plan for fixing the open findings (written 2026-11-12): the order, the
   way, and the decisions to ask Zoltán before coding. Work through it item by item when Zoltán asks for a fix.

## Working with Zoltán

- **Language:** Zoltán Juhász owns the package. Zoltán writes in Hungarian; answer in Hungarian. Code, comments, commit
  messages and every document in this repository are in English.
- **Git and publishing are Zoltán's:** Zoltán manages the git repository and publishes the NuGet package. Do not run
  git commands that change the repository, and do not publish, unless asked. The `/commit.changes` command
  (`.claude/commands/commit.changes.md`) is such a request:
  - it runs the tests in `tests/` first, and does not commit when one fails;
  - it skips the tests when only the knowledge base changed (`CLAUDE.md`, `AI/`, other Markdown files, the instruction
    and prompt files under `.claude/` and `.github/`), and says so;
  - it commits without pushing, with a message that says nothing about the AI.

  `/crt.commit.msg` only writes a commit message into `<branch>.txt` in the repository root.
- **Working style:**
  - one topic at a time;
  - options with a recommendation;
  - facts checked before they are stated;
  - after a work item, report and stop.
- **Keep the knowledge base current:** when a change, a decision or a verification happens, update `AI/` in the same
  step, so the next session can continue from it.
- **No reference to the package's consumers** (Zoltán, 2026-11-11): no name of a product, repository or internal
  decision of a project that uses, or will use, this library, in the code, the documents or this knowledge base.
  Describe a consumer generically ("a Windows service", "a local admin tool"). Allowed:
  - the other `Forge.*` projects;
  - the libraries and tools this package uses or documents: ErrorOr, the `Microsoft.*` libraries, xUnit, Shouldly,
    NSubstitute, and the tools of the checks (OpenSSL, Docker).

## Invariants (do not break)

1. **The public API is a contract.** The package is meant for NuGet (the README's installation section), so code outside
   this repository compiles against it.
   - A new parameter is optional, and its default keeps the earlier behaviour (as `keySize` in 3.1.0: default 2048,
     the size 3.0.0 used).
   - A change that breaks a caller (a removed member, a changed signature, return type or default) raises at least the
     minor version, as 3.1.0 did when every return type became `ErrorOr<T>`.
   - `CertificateFactory.Localhost`, `AesCryptography.Iterations` and `AesCryptography.DefaultOutputLength` are
     constants, and optional-parameter defaults are compiled into the callers: a changed value reaches a consumer only
     when it recompiles.
2. **Dependency-light.** `Forge.Next.Shared` is the only package reference, the same on every target:

   | Target | Package references | Through `Forge.Next.Shared` 3.3.2 |
   | --- | --- | --- |
   | `net8.0` | `Forge.Next.Shared` 3.3.2 | `ErrorOr` 2.1.1, `Microsoft.Extensions.Logging.Abstractions` 8.0.0 |
   | `net9.0` | `Forge.Next.Shared` 3.3.2 | `ErrorOr` 2.1.1, `Microsoft.Extensions.Logging.Abstractions` 9.0.0 |
   | `net10.0` | `Forge.Next.Shared` 3.3.2 | `ErrorOr` 2.1.1, `Microsoft.Extensions.Logging.Abstractions` 10.0.0 |
   | `net11.0` | `Forge.Next.Shared` 3.3.2 | `ErrorOr` 2.1.1 (the .NET 11 shared framework carries `Microsoft.Extensions.Logging.Abstractions`, so Forge.Next.Shared's `net11.0` group does not list it) |

   The code uses `ErrorOr` and, from Forge.Next.Shared, only the `Protect` extension. Do not add a package without
   asking.
3. **One source for every target.** The only per-target code is `#if NET8_0` in `CertificateFactory.GetFromRawData` and
   `GetFromFile`: `net8.0` loads with the `X509Certificate2` constructor, the later targets with
   `X509CertificateLoader`, which `net8.0` lacks and which replaces the constructors .NET 9 marks obsolete
   (`SYSLIB0057`). `NET8_0` is defined for `net8.0` only, so a new target takes the loader branch. Both branches use
   the same storage flags; keep them equal.
4. **No method throws.** Every public method returns `ErrorOr<T>`:
   - the work runs inside Forge.Next.Shared's `Protect`, which turns every exception into `Unexpected` errors, one per
     exception in the inner-exception chain, with the metadata `type`, `message` and `stackTrace`;
   - `Validation` only for a null `password` or `salt` in `AesCryptography`, with the parameter's name as the
     description; `NotFound` only from `FindByThumbprint`;
   - `AesDecrypt` returns an error only for a null password. Every failure it detects (a malformed or undecodable
     payload, invalid parameters, a padding error after a wrong password) returns the input unchanged, by design (the
     README; the 3.1.0 commit: "so a wrong password never discloses the plaintext"). A wrong password is not always
     detected (see `AI/OPEN.md`).

   Moving a case between "error", "success" and "the input unchanged" is a behaviour change: version and README.
5. **The AES payload is stored data.** `AesEncrypt` returns `<Base64 IV>:<Base64 ciphertext>`:
   - AES-CBC with PKCS#7 padding over the UTF-8 bytes of the content, with a random 16-byte IV per call
     (`Aes.Create()`);
   - the key is PBKDF2 (`Rfc2898DeriveBytes.Pbkdf2`) of the UTF-8 password, with the UTF-8 bytes of the IV's Base64
     text as the salt; the defaults: HMAC-SHA-256, 100,000 iterations, 32 bytes (AES-256);
   - the payload records none of these parameters, and has no version marker and no MAC.

   Changing the format, the salt rule or a default makes the existing payloads undecryptable, and `AesDecrypt` would
   hide it by returning them unchanged. Do not change any of it silently: a new format needs a marker that tells it
   apart from this one, and this one must stay readable. Ask Zoltán first.
6. **The certificate profile is behaviour.** `CreateSelfSigned` (and so `GetForLocalhost`) produces, as the README
   documents (the tests check most of it):
   - an RSA key, 2048 bits by default; a SHA-256 signature with PKCS#1 v1.5 padding;
   - non-critical extensions: the key usages `DigitalSignature | KeyEncipherment | DataEncipherment`, the TLS server
     authentication EKU (`1.3.6.1.5.5.7.3.1`), basic constraints "not a CA", a subject key identifier;
   - the Subject Alternative Names: the caller's entries (an IP literal as an IP entry; `127.0.0.1`, `::1`,
     `localhost`, `*` and the machine name skipped, case-insensitively), then always `127.0.0.1`, `::1`, `0.0.0.0`,
     `::`, `0.0.0.0`, `localhost` and the machine name;
   - the friendly name on Windows only.

   The password overload of `CreateSelfSigned`, `GetFromRawData` and `GetFromFile` load with
   `Exportable | PersistKeySet | MachineKeySet`. A change to any of this changes what consumers get: version and
   README.
7. **Secrets stay out of errors, logs and strings.** The package logs nothing; keep it so. No password, salt, key, PFX
   content or plaintext goes into an error's description or metadata: the validation errors name the parameter, never
   its value.

## Conventions

- **Code style:**
  - explicit types (no `var`; not enforced, there is no `.editorconfig`), file-scoped namespaces, one type per file;
  - one namespace, `Forge.Next.Security`; the three classes are `public static`;
  - `LangVersion` 12 for every target, `Nullable` and `ImplicitUsings` on;
  - the work of each public method runs inside `Protect`, directly or through another public method, chained with
    `ErrorOr`'s `Then`, `ThenDo` and `Else`;
  - XML documentation on every public member (`GenerateDocumentationFile`); the build reports a missing one (CS1591).
- **Tests** (`tests/Forge.Next.Security.Tests`, the same targets as the library: `net8.0`, `net9.0`, `net10.0`,
  `net11.0`; a test that differs per target asserts each target's result with `#if NET8_0`):
  - xUnit 2, Shouldly, NSubstitute (referenced, not used: the classes are static and have no collaborators);
  - one test class per source file (`<File>Tests`; `CertificateStoreTests` tests `CertificateAccess`); test methods
    named after the tested member with a `Test` suffix (`AesDecryptTest`), other cases as `<Member>_<Case>_Test`
    (`AesDecrypt_WrongPasswordDoesNotRevealPlaintext_Test`); richly commented (see `prompts/init_tests.txt`);
  - the store tests use the real `CurrentUser\My` store and remove what they add; the PFX tests import into the
    machine key store, and `CertificateFactoryTests.Dispose` deletes the persisted keys after each test: wrap every
    new successful PFX load in `DeleteKeyAfterTest`, or each run leaves a key file per load and target.
- **Before handing over a change:**
  - a 0-warning build of the solution, all targets;
  - all tests;
  - when a target was added or a dependency changed: the package's `.nuspec` dependency groups checked against the
    table above (see `AI/VERIFICATION.md`).
- **Documentation:** every public change is reflected in `README.md` in the same step: the signature, an example, and
  the notes. The README is packed into the package.
- **Release:**
  1. Raise `AssemblyVersion` in `Forge.Next.Security/Forge.Next.Security.csproj` (`Version` and `FileVersion` follow
     it). The README names no version number, so it needs no change for it.
  2. Run `dotnet build -c Release`; it writes the package to `artifacts/` (`GeneratePackageOnBuild` is on for Release
     only, `PackageOutputPath` is `../artifacts/`). A Release build overwrites the package of the current version
     there, so build a published version again only on purpose. To check a package without touching `artifacts/`,
     build the library project with `-p:PackageOutputPath=<another folder>\`. `artifacts/` is ignored by git, so
     `git status` does not show a change there: compare the files' hashes.
  3. Zoltán publishes it.
