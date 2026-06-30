using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using Xunit;

namespace Forge.Next.Security.Tests;

/// <summary>
/// Unit tests for <see cref="CertificateFactory"/>.
///
/// <para>
/// <see cref="CertificateFactory"/> is a <c>static</c> utility class that builds, exports and
/// re-imports self-signed X.509 certificates. It has no injectable collaborators, therefore there
/// is nothing for a mocking library such as NSubstitute to substitute here: every test below
/// exercises the real .NET cryptographic primitives end-to-end and asserts on the resulting
/// <see cref="X509Certificate2"/>. NSubstitute is reserved for the (future) types that take
/// abstractions as dependencies.
/// </para>
///
/// <para>
/// Assertions are written with Shouldly because that is the assertion library referenced by the
/// test project. The PFX round-trip helpers (<see cref="CertificateFactory.GetFromRawData"/> and
/// <see cref="CertificateFactory.GetFromFile"/>) load the key with <c>X509KeyStorageFlags.MachineKeySet</c>,
/// which on Windows requires write access to the machine key container; the tests assume they are
/// executed in such an environment (which is the case on a standard developer workstation).
/// </para>
/// </summary>
public class CertificateFactoryTests
{
    // ---------------------------------------------------------------------------------------------
    // Shared test data. Using constants keeps the individual tests focused on the behaviour under
    // test rather than on the noise of arbitrary literal values.
    // ---------------------------------------------------------------------------------------------

    /// <summary>A representative X.500 subject used by most tests.</summary>
    private const string Subject = "CN=Forge Unit Test";

    /// <summary>A representative Windows friendly name used by most tests.</summary>
    private const string FriendlyName = "Forge Unit Test Certificate";

    /// <summary>A representative password used for the PFX round-trip tests.</summary>
    private const string Password = "P@ssw0rd!";

    /// <summary>
    /// Tolerance applied when comparing certificate validity timestamps. X.509 stores validity
    /// boundaries with whole-second precision, so the sub-second part of the requested
    /// <see cref="DateTime"/> is truncated when it is encoded into the certificate. A two second
    /// window comfortably absorbs that rounding without weakening the assertion.
    /// </summary>
    private static readonly TimeSpan ValidityTolerance = TimeSpan.FromSeconds(2);

    #region Constants

    /// <summary>
    /// The publicly exposed <see cref="CertificateFactory.Localhost"/> constant must always be the
    /// lower-case DNS label "localhost"; other code (and the SAN reservation logic) relies on it.
    /// </summary>
    [Fact]
    public void LocalhostTest()
    {
        // The constant is a contract: assert its exact value so an accidental change is caught.
        CertificateFactory.Localhost.ShouldBe("localhost");
    }

    #endregion

    #region CreateSelfSigned (no password)

    /// <summary>
    /// The basic overload must return a usable certificate that owns its private key and carries the
    /// requested subject.
    /// </summary>
    [Fact]
    public void CreateSelfSignedTest()
    {
        // Act: create an ephemeral (in-memory) self-signed certificate valid for one day.
        X509Certificate2 certificate = CreateCertificate();

        // Assert: a certificate instance was produced.
        certificate.ShouldNotBeNull();

        // Assert: the subject distinguished name was honoured verbatim.
        certificate.Subject.ShouldBe(Subject);

        // Assert: a self-signed certificate is its own issuer.
        certificate.Issuer.ShouldBe(Subject);

        // Assert: the certificate carries the freshly generated RSA private key.
        certificate.HasPrivateKey.ShouldBeTrue();
    }

    /// <summary>
    /// A <c>null</c> subject must not throw: the factory coalesces it to <see cref="string.Empty"/>,
    /// which yields a certificate with an empty subject distinguished name.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_NullSubjectDefaultsToEmpty_Test()
    {
        // Act: pass a null subject (the null-forgiving operator silences the nullable warning since
        // the parameter is declared non-nullable but the implementation defensively handles null).
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            null!,
            FriendlyName,
            Array.Empty<string>(),
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(1));

        // Assert: the empty X500 name materialises as an empty subject string.
        certificate.Subject.ShouldBe(string.Empty);
    }

    /// <summary>
    /// The requested start and end instants must be encoded into the certificate's validity window.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_SetsValidityPeriod_Test()
    {
        // Arrange: choose explicit UTC boundaries. UTC is used so the DateTimeOffset conversion
        // inside the factory carries a zero offset, making the comparison below unambiguous.
        DateTime start = DateTime.UtcNow.AddDays(-3);
        DateTime end = DateTime.UtcNow.AddDays(3);

        // Act.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, Array.Empty<string>(), start, end);

        // Assert: NotBefore/NotAfter are surfaced by X509Certificate2 in local time, so normalise to
        // UTC before comparing. The tolerance absorbs the whole-second truncation described above.
        certificate.NotBefore.ToUniversalTime().ShouldBe(start, ValidityTolerance);
        certificate.NotAfter.ToUniversalTime().ShouldBe(end, ValidityTolerance);
    }

    /// <summary>
    /// On Windows the friendly name is applied to the certificate; on other platforms the property
    /// is not supported and the factory deliberately skips it.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_AppliesFriendlyNameOnWindows_Test()
    {
        // Act.
        X509Certificate2 certificate = CreateCertificate();

        // Assert: branch on the running OS because the friendly name is a Windows-only concept.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // On Windows the requested friendly name must have been stored on the certificate.
            certificate.FriendlyName.ShouldBe(FriendlyName);
        }
        else
        {
            // On non-Windows platforms the factory leaves the friendly name untouched (empty).
            certificate.FriendlyName.ShouldBe(string.Empty);
        }
    }

    /// <summary>
    /// The factory hard-codes a 2048-bit RSA key; assert the generated public key reflects that.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_Uses2048BitRsaKey_Test()
    {
        // Act.
        X509Certificate2 certificate = CreateCertificate();

        // Read the RSA public key off the certificate. The 'using' guarantees the key handle is
        // released promptly even though these are managed objects.
        using RSA? publicKey = certificate.GetRSAPublicKey();

        // Assert: the key exists and is exactly 2048 bits, matching RSA.Create(2048) in the factory.
        publicKey.ShouldNotBeNull();
        publicKey.KeySize.ShouldBe(2048);
    }

    /// <summary>
    /// The certificate request is built with SHA-256 + PKCS#1 RSA, so the signature algorithm OID
    /// must be sha256RSA (1.2.840.113549.1.1.11).
    /// </summary>
    [Fact]
    public void CreateSelfSigned_UsesSha256RsaSignature_Test()
    {
        // Act.
        X509Certificate2 certificate = CreateCertificate();

        // Assert: compare against the well-known OID for sha256RSA. Comparing the OID (rather than
        // the localisable friendly name) keeps the assertion culture-independent.
        certificate.SignatureAlgorithm.Value.ShouldBe("1.2.840.113549.1.1.11");
    }

    /// <summary>
    /// The factory adds an Enhanced Key Usage extension marking the certificate for TLS server
    /// authentication (OID 1.3.6.1.5.5.7.3.1).
    /// </summary>
    [Fact]
    public void CreateSelfSigned_AddsServerAuthenticationEku_Test()
    {
        // Act.
        X509Certificate2 certificate = CreateCertificate();

        // Locate the EKU extension via the private helper.
        X509EnhancedKeyUsageExtension eku = GetEnhancedKeyUsage(certificate);

        // Assert: the server-authentication OID is present among the enhanced key usages.
        eku.EnhancedKeyUsages
            .Cast<Oid>()
            .Select(oid => oid.Value)
            .ShouldContain("1.3.6.1.5.5.7.3.1");
    }

    /// <summary>
    /// The Key Usage extension must enable digital signature, key encipherment and data
    /// encipherment — the flags required for a TLS server certificate that also encrypts data.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_AddsExpectedKeyUsages_Test()
    {
        // Act.
        X509Certificate2 certificate = CreateCertificate();

        // Locate the Key Usage extension via the private helper.
        X509KeyUsageExtension keyUsage = GetKeyUsage(certificate);

        // Compose the exact set of flags the factory requests so the assertion is explicit.
        X509KeyUsageFlags expected =
            X509KeyUsageFlags.DigitalSignature |
            X509KeyUsageFlags.KeyEncipherment |
            X509KeyUsageFlags.DataEncipherment;

        // Assert: the stored key usages equal the expected combination (no more, no less).
        keyUsage.KeyUsages.ShouldBe(expected);
    }

    /// <summary>
    /// A leaf certificate must not be a Certificate Authority; the Basic Constraints extension is
    /// added with <c>certificateAuthority = false</c>.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_IsNotCertificateAuthority_Test()
    {
        // Act.
        X509Certificate2 certificate = CreateCertificate();

        // Locate the Basic Constraints extension via the private helper.
        X509BasicConstraintsExtension basicConstraints = GetBasicConstraints(certificate);

        // Assert: the certificate is explicitly flagged as a non-CA (end-entity) certificate.
        basicConstraints.CertificateAuthority.ShouldBeFalse();
    }

    /// <summary>
    /// A custom, non-reserved DNS name supplied by the caller must end up in the Subject Alternative
    /// Name extension exactly once.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_AddsCustomDnsName_Test()
    {
        // Arrange: "example.com" is neither an IP, nor a reserved name, nor a default entry.
        const string customDns = "example.com";

        // Act.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, new[] { customDns },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        // Read back every SAN entry.
        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: the custom DNS name is present, and present exactly once (proving it was not
        // duplicated by also matching a default entry).
        alternateNames.ShouldContain(customDns);
        alternateNames.Count(name => name == customDns).ShouldBe(1);
    }

    /// <summary>
    /// A custom DNS entry that parses as an IP address must be added as an IP SAN entry, not a DNS
    /// SAN entry.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_AddsCustomIpAddress_Test()
    {
        // Arrange: a routable, non-loopback IPv4 address that is not part of the default set.
        const string customIp = "192.168.1.5";

        // Act.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, new[] { customIp },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        // GetAlternateNames renders IP SAN entries via IPAddress.ToString(), so the textual form
        // round-trips back to the same string.
        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: the IP appears exactly once.
        alternateNames.ShouldContain(customIp);
        alternateNames.Count(name => name == customIp).ShouldBe(1);
    }

    /// <summary>
    /// Passing a loopback IP as a custom DNS entry must be suppressed by <c>IsLoopbackIpAddress</c>:
    /// the loopback address is still present (the default SAN entries always add it) but only once,
    /// proving the custom entry was dropped rather than appended a second time.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_SkipsLoopbackCustomIpAddress_Test()
    {
        // Arrange: 127.0.0.1 is the IPv4 loopback that the default SAN set already contributes.
        const string loopback = "127.0.0.1";

        // Act: supply the loopback explicitly as a "custom" entry.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, new[] { loopback },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: exactly one loopback entry (the default one). Had the custom entry not been
        // skipped, it would appear twice.
        alternateNames.Count(name => name == loopback).ShouldBe(1);
    }

    /// <summary>
    /// The reserved name "localhost" supplied as a custom entry must be skipped; it still appears
    /// once because <c>AppendDefaultSanEntries</c> always adds it.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_SkipsReservedLocalhostDnsName_Test()
    {
        // Act: supply "localhost" explicitly.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, new[] { CertificateFactory.Localhost },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: only the single default "localhost" entry exists; the custom one was suppressed.
        alternateNames.Count(name => name == CertificateFactory.Localhost).ShouldBe(1);
    }

    /// <summary>
    /// The wildcard "*" is treated as a reserved name and must be skipped entirely; unlike
    /// "localhost" it has no default counterpart, so it must be completely absent from the SANs.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_SkipsWildcardDnsName_Test()
    {
        // Act: supply "*" as a custom entry.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, new[] { "*" },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: the wildcard never made it into the certificate.
        alternateNames.ShouldNotContain("*");
    }

    /// <summary>
    /// The current machine name is reserved and must be skipped when supplied as a custom entry; it
    /// still appears once because the default SAN entries always add the machine name.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_SkipsMachineNameDnsName_Test()
    {
        // Arrange: the reservation logic compares against Environment.MachineName.
        string machineName = Environment.MachineName;

        // Act: supply the machine name explicitly.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, new[] { machineName },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: exactly one machine-name entry (the default one); the custom duplicate was skipped.
        alternateNames.Count(name => name == machineName).ShouldBe(1);
    }

    /// <summary>
    /// Regardless of the caller-supplied names, the factory always seeds a fixed set of default SAN
    /// entries so the certificate is valid for local development out of the box.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_AddsDefaultSubjectAlternativeNames_Test()
    {
        // Act: create a certificate with no custom names at all.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, Array.Empty<string>(),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: each documented default loopback/any address and DNS label is present.
        alternateNames.ShouldContain("127.0.0.1");          // IPAddress.Loopback
        alternateNames.ShouldContain("::1");                // IPAddress.IPv6Loopback
        alternateNames.ShouldContain("0.0.0.0");            // IPAddress.Parse("0.0.0.0") / IPAddress.Any
        alternateNames.ShouldContain("::");                 // IPAddress.IPv6Any
        alternateNames.ShouldContain(CertificateFactory.Localhost);
        alternateNames.ShouldContain(Environment.MachineName);
    }

    #endregion

    #region CreateSelfSigned (with password)

    /// <summary>
    /// The password overload creates the certificate, exports it to a password-protected PFX and
    /// re-imports it. The result must still own its private key and must preserve the subject and
    /// the Subject Alternative Names of the original certificate.
    /// </summary>
    [Fact]
    public void CreateSelfSigned_WithPassword_Test()
    {
        // Arrange.
        const string customDns = "secure.example";

        // Act: the overload performs an export+import round-trip internally.
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            Subject, FriendlyName, new[] { customDns },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1), Password);

        // Assert: round-tripping through a PFX preserves the private key.
        certificate.HasPrivateKey.ShouldBeTrue();

        // Assert: the subject survives the round-trip.
        certificate.Subject.ShouldBe(Subject);

        // Assert: the SAN entries survive the round-trip as well.
        CertificateAccess.GetAlternateNames(certificate).ShouldContain(customDns);
    }

    #endregion

    #region ExportToPfxRawData

    /// <summary>
    /// Exporting to PFX raw data must yield a non-empty buffer that re-imports (with the same
    /// password) to a certificate with the identical thumbprint and an intact private key.
    /// </summary>
    [Fact]
    public void ExportToPfxRawDataTest()
    {
        // Arrange: an ephemeral certificate that owns its private key.
        X509Certificate2 certificate = CreateCertificate();

        // Act: export the full certificate + private key as a PKCS#12/PFX blob.
        byte[] pfx = CertificateFactory.ExportToPfxRawData(certificate, Password);

        // Assert: the export produced bytes.
        pfx.ShouldNotBeNull();
        pfx.Length.ShouldBeGreaterThan(0);

        // Assert: the blob round-trips back to an equivalent certificate (same thumbprint, with key).
        X509Certificate2 reimported = CertificateFactory.GetFromRawData(pfx, Password);
        reimported.Thumbprint.ShouldBe(certificate.Thumbprint);
        reimported.HasPrivateKey.ShouldBeTrue();
    }

    #endregion

    #region ExportToCerFile

    /// <summary>
    /// Exporting to a DER (.cer) blob must yield the public certificate only: re-importing it
    /// produces a certificate with the same thumbprint but no private key.
    /// </summary>
    [Fact]
    public void ExportToCerFileTest()
    {
        // Arrange.
        X509Certificate2 certificate = CreateCertificate();

        // Act: export the public certificate in DER encoding.
        byte[] cer = CertificateFactory.ExportToCerFile(certificate);

        // Assert: bytes were produced.
        cer.ShouldNotBeNull();
        cer.Length.ShouldBeGreaterThan(0);

        // Re-load the DER bytes as a public-only certificate.
        X509Certificate2 reimported = X509CertificateLoader.LoadCertificate(cer);

        // Assert: identity is preserved but the private key is intentionally absent.
        reimported.Thumbprint.ShouldBe(certificate.Thumbprint);
        reimported.HasPrivateKey.ShouldBeFalse();
    }

    #endregion

    #region GetForLocalhost

    /// <summary>
    /// <see cref="CertificateFactory.GetForLocalhost"/> must produce a certificate that is already
    /// valid (starts in the past), effectively never expires (year 9999), carries the supplied
    /// subject and is valid for "localhost".
    /// </summary>
    [Fact]
    public void GetForLocalhostTest()
    {
        // Act.
        X509Certificate2 certificate = CertificateFactory.GetForLocalhost(Subject, FriendlyName);

        // Assert: subject honoured.
        certificate.Subject.ShouldBe(Subject);

        // Assert: the certificate became valid in the past (start time = UtcNow - 1 day).
        certificate.NotBefore.ToUniversalTime().ShouldBeLessThan(DateTime.UtcNow);

        // Assert: the certificate uses DateTime.MaxValue as its expiry, i.e. the far-future year 9999.
        certificate.NotAfter.ToUniversalTime().Year.ShouldBe(9999);

        // Assert: it is usable for localhost connections.
        CertificateAccess.GetAlternateNames(certificate).ShouldContain(CertificateFactory.Localhost);
    }

    #endregion

    #region GetFromRawData

    /// <summary>
    /// Loading a certificate from PFX raw data with the correct password must return a certificate
    /// equivalent to the original (same thumbprint) that owns its private key.
    /// </summary>
    [Fact]
    public void GetFromRawDataTest()
    {
        // Arrange: produce a PFX blob from an ephemeral certificate.
        X509Certificate2 original = CreateCertificate();
        byte[] pfx = CertificateFactory.ExportToPfxRawData(original, Password);

        // Act.
        X509Certificate2 loaded = CertificateFactory.GetFromRawData(pfx, Password);

        // Assert: identity preserved and the private key was imported.
        loaded.Thumbprint.ShouldBe(original.Thumbprint);
        loaded.HasPrivateKey.ShouldBeTrue();
    }

    /// <summary>
    /// Supplying the wrong password when loading a PFX must surface as a
    /// <see cref="CryptographicException"/>.
    /// </summary>
    [Fact]
    public void GetFromRawData_WrongPassword_Throws_Test()
    {
        // Arrange: export with one password...
        X509Certificate2 original = CreateCertificate();
        byte[] pfx = CertificateFactory.ExportToPfxRawData(original, Password);

        // Act & Assert: ...then attempt to load with a different password.
        Should.Throw<CryptographicException>(() => CertificateFactory.GetFromRawData(pfx, "not-the-password"));
    }

    #endregion

    #region GetFromFile

    /// <summary>
    /// Loading a certificate from a PFX file on disk must return a certificate equivalent to the
    /// original (same thumbprint) that owns its private key.
    /// </summary>
    [Fact]
    public void GetFromFileTest()
    {
        // Arrange: write a PFX blob to a unique temporary file.
        X509Certificate2 original = CreateCertificate();
        byte[] pfx = CertificateFactory.ExportToPfxRawData(original, Password);
        string path = Path.Combine(Path.GetTempPath(), $"forge-cert-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(path, pfx);

        try
        {
            // Act.
            X509Certificate2 loaded = CertificateFactory.GetFromFile(path, Password);

            // Assert: identity preserved and the private key was imported.
            loaded.Thumbprint.ShouldBe(original.Thumbprint);
            loaded.HasPrivateKey.ShouldBeTrue();
        }
        finally
        {
            // Always clean up the temporary file regardless of the assertion outcome.
            File.Delete(path);
        }
    }

    /// <summary>
    /// Loading a PFX file with the wrong password must surface as a
    /// <see cref="CryptographicException"/>.
    /// </summary>
    [Fact]
    public void GetFromFile_WrongPassword_Throws_Test()
    {
        // Arrange.
        X509Certificate2 original = CreateCertificate();
        byte[] pfx = CertificateFactory.ExportToPfxRawData(original, Password);
        string path = Path.Combine(Path.GetTempPath(), $"forge-cert-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(path, pfx);

        try
        {
            // Act & Assert.
            Should.Throw<CryptographicException>(() => CertificateFactory.GetFromFile(path, "not-the-password"));
        }
        finally
        {
            File.Delete(path);
        }
    }

    #endregion

    #region Private helpers

    /// <summary>
    /// Creates a standard ephemeral self-signed certificate (subject <see cref="Subject"/>, friendly
    /// name <see cref="FriendlyName"/>, no custom SAN names, valid from yesterday to tomorrow).
    /// Centralising the "happy path" creation keeps the individual tests terse and consistent.
    /// </summary>
    /// <returns>A freshly generated <see cref="X509Certificate2"/> owning its private key.</returns>
    private static X509Certificate2 CreateCertificate()
    {
        // A one-day-either-side validity window keeps the certificate unambiguously "currently valid"
        // without depending on the host clock being perfectly aligned.
        return CertificateFactory.CreateSelfSigned(
            Subject,
            FriendlyName,
            Array.Empty<string>(),
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(1));
    }

    /// <summary>
    /// Locates the <see cref="X509KeyUsageExtension"/> on a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>The key usage extension.</returns>
    /// <remarks>
    /// The extension collection is heterogeneous, so we filter by concrete type. The test fails fast
    /// with a clear message if the expected extension is missing rather than returning null.
    /// </remarks>
    private static X509KeyUsageExtension GetKeyUsage(X509Certificate2 certificate)
    {
        X509KeyUsageExtension? extension = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();

        extension.ShouldNotBeNull("The certificate is expected to carry a Key Usage extension.");
        return extension;
    }

    /// <summary>
    /// Locates the <see cref="X509EnhancedKeyUsageExtension"/> on a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>The enhanced key usage extension.</returns>
    private static X509EnhancedKeyUsageExtension GetEnhancedKeyUsage(X509Certificate2 certificate)
    {
        X509EnhancedKeyUsageExtension? extension = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        extension.ShouldNotBeNull("The certificate is expected to carry an Enhanced Key Usage extension.");
        return extension;
    }

    /// <summary>
    /// Locates the <see cref="X509BasicConstraintsExtension"/> on a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>The basic constraints extension.</returns>
    private static X509BasicConstraintsExtension GetBasicConstraints(X509Certificate2 certificate)
    {
        X509BasicConstraintsExtension? extension = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();

        extension.ShouldNotBeNull("The certificate is expected to carry a Basic Constraints extension.");
        return extension;
    }

    #endregion
}
