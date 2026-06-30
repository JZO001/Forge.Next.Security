using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using Xunit;

namespace Forge.Next.Security.Tests;

/// <summary>
/// Unit tests for <see cref="CertificateAccess"/> (declared in <c>CertificateStore.cs</c>).
///
/// <para>
/// <see cref="CertificateAccess"/> is a <c>static</c> helper around <see cref="X509Store"/>. Like
/// <see cref="CertificateFactory"/> it has no injectable collaborators, so there is nothing for a
/// mocking library such as NSubstitute to substitute: the OS certificate store is a process-wide
/// singleton that cannot be intercepted. The store-mutating tests therefore behave as small
/// integration tests against the per-user store (<see cref="StoreName.My"/> /
/// <see cref="StoreLocation.CurrentUser"/>), which is writable without elevation. Every test that
/// adds a certificate removes it again in a <c>finally</c>/<c>Dispose</c> block so the store is
/// left exactly as it was found.
/// </para>
///
/// <para>
/// To avoid clashing with any pre-existing certificates in the developer's store, each test uses a
/// freshly generated certificate and queries by its unique thumbprint or a unique GUID-based DNS
/// name; assertions check for the <em>presence</em> of that specific certificate rather than for an
/// absolute store size. xUnit runs the methods of a single test class sequentially, so the
/// store-mutating tests below never run concurrently with one another.
/// </para>
/// </summary>
public class CertificateStoreTests
{
    // ---------------------------------------------------------------------------------------------
    // The per-user "My" (Personal) store is the safe sandbox for these tests: it can be opened
    // read/write without administrator rights and is the natural home for personal certificates.
    // ---------------------------------------------------------------------------------------------

    /// <summary>The store name used by all store-touching tests.</summary>
    private const StoreName TestStoreName = StoreName.My;

    /// <summary>The store location used by all store-touching tests.</summary>
    private const StoreLocation TestStoreLocation = StoreLocation.CurrentUser;

    #region GetAlternateNames

    /// <summary>
    /// <see cref="CertificateAccess.GetAlternateNames"/> must enumerate both the IP-address and the
    /// DNS-name entries from the certificate's Subject Alternative Name extension.
    /// </summary>
    [Fact]
    public void GetAlternateNamesTest()
    {
        // Arrange: build a certificate with a known custom DNS name and a known custom IP address.
        const string dns = "alt.example";
        const string ip = "10.20.30.40";
        X509Certificate2 certificate = CertificateFactory.CreateSelfSigned(
            "CN=AltNames", "AltNames", new[] { dns, ip },
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1));

        // Act.
        List<string> alternateNames = CertificateAccess.GetAlternateNames(certificate).ToList();

        // Assert: both the DNS name and the IP address were extracted from the SAN extension.
        alternateNames.ShouldContain(dns);
        alternateNames.ShouldContain(ip);
    }

    /// <summary>
    /// A certificate that has no Subject Alternative Name extension at all must yield an empty
    /// sequence rather than throwing.
    /// </summary>
    [Fact]
    public void GetAlternateNames_ReturnsEmptyForCertificateWithoutSan_Test()
    {
        // Arrange: build a bare self-signed certificate that deliberately omits the SAN extension.
        using X509Certificate2 certificate = CreateCertificateWithoutSan();

        // Act.
        IEnumerable<string> alternateNames = CertificateAccess.GetAlternateNames(certificate);

        // Assert: no SAN extension means no alternate names.
        alternateNames.ShouldBeEmpty();
    }

    #endregion

    #region AddToStore / FindByThumbprint / RemoveFromStore

    /// <summary>
    /// Adding a certificate to the store must make it discoverable by its thumbprint.
    /// </summary>
    [Fact]
    public void AddToStoreTest()
    {
        // Arrange: create a certificate and add it to the per-user store via the scope helper, which
        // guarantees removal afterwards.
        using X509Certificate2 certificate = CreateStoreCertificate();
        using (new StoreCertificateScope(certificate))
        {
            // Act: look the certificate up again straight from the store.
            X509Certificate2? found = CertificateAccess.FindByThumbprint(
                TestStoreName, TestStoreLocation, certificate.Thumbprint);

            // Assert: the certificate we just added is present.
            found.ShouldNotBeNull();
            found.Thumbprint.ShouldBe(certificate.Thumbprint);
        }
    }

    /// <summary>
    /// <see cref="CertificateAccess.FindByThumbprint"/> must return the matching certificate when it
    /// exists in the store.
    /// </summary>
    [Fact]
    public void FindByThumbprintTest()
    {
        // Arrange.
        using X509Certificate2 certificate = CreateStoreCertificate();
        using (new StoreCertificateScope(certificate))
        {
            // Act.
            X509Certificate2? found = CertificateAccess.FindByThumbprint(
                TestStoreName, TestStoreLocation, certificate.Thumbprint);

            // Assert: a non-null certificate with the requested thumbprint is returned.
            found.ShouldNotBeNull();
            found.Thumbprint.ShouldBe(certificate.Thumbprint);
        }
    }

    /// <summary>
    /// <see cref="CertificateAccess.FindByThumbprint"/> must return <c>null</c> when no certificate
    /// with the requested thumbprint is present (the <c>Count &gt; 0</c> guard returns null).
    /// </summary>
    [Fact]
    public void FindByThumbprint_ReturnsNullWhenNotFound_Test()
    {
        // Arrange: a syntactically valid but almost-certainly-absent 40-hex-character thumbprint.
        string missingThumbprint = new string('A', 40);

        // Act.
        X509Certificate2? found = CertificateAccess.FindByThumbprint(
            TestStoreName, TestStoreLocation, missingThumbprint);

        // Assert: nothing matched, so null is returned.
        found.ShouldBeNull();
    }

    /// <summary>
    /// <see cref="CertificateAccess.RemoveFromStore"/> must remove a previously added certificate so
    /// that a subsequent lookup no longer finds it.
    /// </summary>
    [Fact]
    public void RemoveFromStoreTest()
    {
        // Arrange: add a certificate to the store ourselves (not via the scope helper, because this
        // test is specifically exercising removal).
        using X509Certificate2 certificate = CreateStoreCertificate();
        CertificateAccess.AddToStore(certificate, TestStoreName, TestStoreLocation);

        // Sanity precondition: it really is in the store before we remove it.
        CertificateAccess.FindByThumbprint(TestStoreName, TestStoreLocation, certificate.Thumbprint)
            .ShouldNotBeNull();

        // Act.
        CertificateAccess.RemoveFromStore(certificate.Thumbprint, TestStoreName, TestStoreLocation);

        // Assert: the certificate can no longer be found.
        CertificateAccess.FindByThumbprint(TestStoreName, TestStoreLocation, certificate.Thumbprint)
            .ShouldBeNull();
    }

    /// <summary>
    /// Removing a thumbprint that is not present in the store must be a harmless no-op (the
    /// <c>Count &gt; 0</c> guard prevents touching a non-existent certificate).
    /// </summary>
    [Fact]
    public void RemoveFromStore_NonExistentThumbprint_DoesNotThrow_Test()
    {
        // Arrange: a thumbprint that does not correspond to any certificate.
        string missingThumbprint = new string('B', 40);

        // Act & Assert: the call completes without throwing.
        Should.NotThrow(() => CertificateAccess.RemoveFromStore(
            missingThumbprint, TestStoreName, TestStoreLocation));
    }

    #endregion

    #region GetAllFromStore

    /// <summary>
    /// <see cref="CertificateAccess.GetAllFromStore"/> must return every certificate in the store,
    /// including one we have just added.
    /// </summary>
    [Fact]
    public void GetAllFromStoreTest()
    {
        // Arrange.
        using X509Certificate2 certificate = CreateStoreCertificate();
        using (new StoreCertificateScope(certificate))
        {
            // Act.
            List<X509Certificate2> all = CertificateAccess
                .GetAllFromStore(TestStoreName, TestStoreLocation)
                .ToList();

            // Assert: our certificate is among the returned set (matched by thumbprint, since the
            // shared store may legitimately contain other certificates as well).
            all.ShouldContain(cert => cert.Thumbprint == certificate.Thumbprint);
        }
    }

    #endregion

    #region FindByDnsNames

    /// <summary>
    /// <see cref="CertificateAccess.FindByDnsNames"/> must return certificates whose SAN entries
    /// contain all of the requested DNS names.
    /// </summary>
    [Fact]
    public void FindByDnsNamesTest()
    {
        // Arrange: a globally unique DNS name guarantees only our certificate can match it.
        string uniqueDns = UniqueDnsName();
        using X509Certificate2 certificate = CreateStoreCertificate(uniqueDns);
        using (new StoreCertificateScope(certificate))
        {
            // Act.
            List<X509Certificate2> matches = CertificateAccess
                .FindByDnsNames(TestStoreName, TestStoreLocation, new[] { uniqueDns })
                .ToList();

            // Assert: exactly our certificate is returned for this unique name.
            matches.ShouldContain(cert => cert.Thumbprint == certificate.Thumbprint);
        }
    }

    /// <summary>
    /// The DNS-name match must be case-insensitive: both the stored names and the queried names are
    /// lower-cased before comparison, so an upper-cased query still matches.
    /// </summary>
    [Fact]
    public void FindByDnsNames_IsCaseInsensitive_Test()
    {
        // Arrange.
        string uniqueDns = UniqueDnsName();
        using X509Certificate2 certificate = CreateStoreCertificate(uniqueDns);
        using (new StoreCertificateScope(certificate))
        {
            // Act: query using the upper-cased form of the stored (lower-case) DNS name.
            List<X509Certificate2> matches = CertificateAccess
                .FindByDnsNames(TestStoreName, TestStoreLocation, new[] { uniqueDns.ToUpperInvariant() })
                .ToList();

            // Assert: case differences do not prevent the match.
            matches.ShouldContain(cert => cert.Thumbprint == certificate.Thumbprint);
        }
    }

    /// <summary>
    /// A DNS name that no certificate carries must yield no matches.
    /// </summary>
    [Fact]
    public void FindByDnsNames_ReturnsEmptyWhenNoMatch_Test()
    {
        // Arrange: a unique name that we never put into any certificate.
        string missingDns = UniqueDnsName();

        // Act.
        List<X509Certificate2> matches = CertificateAccess
            .FindByDnsNames(TestStoreName, TestStoreLocation, new[] { missingDns })
            .ToList();

        // Assert: nothing matched.
        matches.ShouldBeEmpty();
    }

    /// <summary>
    /// The match uses <c>All</c> semantics: a certificate is only returned when it carries every
    /// requested DNS name. Mixing a present name with an absent one must therefore yield no match.
    /// </summary>
    [Fact]
    public void FindByDnsNames_RequiresAllDnsNames_Test()
    {
        // Arrange: a certificate that carries 'presentDns' but not 'absentDns'.
        string presentDns = UniqueDnsName();
        string absentDns = UniqueDnsName();
        using X509Certificate2 certificate = CreateStoreCertificate(presentDns);
        using (new StoreCertificateScope(certificate))
        {
            // Act: ask for both names at once.
            List<X509Certificate2> matches = CertificateAccess
                .FindByDnsNames(TestStoreName, TestStoreLocation, new[] { presentDns, absentDns })
                .ToList();

            // Assert: because one of the requested names is missing, our certificate is excluded.
            matches.ShouldNotContain(cert => cert.Thumbprint == certificate.Thumbprint);
        }
    }

    #endregion

    #region Private helpers

    /// <summary>
    /// Creates an ephemeral self-signed certificate suitable for store round-trips, optionally
    /// carrying an extra custom DNS name in its SAN extension.
    /// </summary>
    /// <param name="extraDnsName">
    /// An optional additional DNS name to embed; when <c>null</c> only the default SAN entries are
    /// present.
    /// </param>
    /// <returns>A freshly generated certificate owning its private key.</returns>
    private static X509Certificate2 CreateStoreCertificate(string? extraDnsName = null)
    {
        // Forward either an empty SAN list or a single-element list, depending on the caller's need.
        IEnumerable<string> dnsNames = extraDnsName is null
            ? Array.Empty<string>()
            : new[] { extraDnsName };

        return CertificateFactory.CreateSelfSigned(
            "CN=Forge Store Test",
            "Forge Store Test Certificate",
            dnsNames,
            DateTime.UtcNow.AddDays(-1),
            DateTime.UtcNow.AddDays(1));
    }

    /// <summary>
    /// Produces a globally unique, lower-case DNS label so that store queries can target exactly one
    /// certificate even though the per-user store is shared with the developer's real certificates.
    /// </summary>
    /// <returns>A DNS name of the form <c>forge-test-&lt;guid&gt;.example</c>.</returns>
    private static string UniqueDnsName()
    {
        // Guid "N" formatting yields 32 lower-case hex characters: a valid, collision-free DNS label.
        return $"forge-test-{Guid.NewGuid():N}.example";
    }

    /// <summary>
    /// Builds a minimal self-signed certificate that intentionally has no Subject Alternative Name
    /// extension. Used to exercise the "no SAN" branch of
    /// <see cref="CertificateAccess.GetAlternateNames"/>.
    /// </summary>
    /// <returns>A certificate without any SAN extension.</returns>
    private static X509Certificate2 CreateCertificateWithoutSan()
    {
        // Generate a throwaway RSA key; 'using' ensures the key material is disposed once the
        // certificate has been created (the certificate keeps its own copy of the key).
        using RSA rsa = RSA.Create(2048);

        // Build a certificate request with only the subject and key — no extensions are added, so the
        // resulting certificate has no SAN extension for GetAlternateNames to enumerate.
        CertificateRequest request = new(
            "CN=NoSan",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Self-sign with a simple one-day-either-side validity window.
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
    }

    /// <summary>
    /// A small RAII-style helper that adds a certificate to the test store on construction and
    /// removes it again on disposal. Wrapping the store mutation in a <c>using</c> block guarantees
    /// the certificate is cleaned up even if an assertion fails midway through a test.
    /// </summary>
    private sealed class StoreCertificateScope : IDisposable
    {
        /// <summary>The thumbprint to remove on disposal.</summary>
        private readonly string _thumbprint;

        /// <summary>
        /// Adds <paramref name="certificate"/> to the per-user test store.
        /// </summary>
        /// <param name="certificate">The certificate to add (and later remove).</param>
        public StoreCertificateScope(X509Certificate2 certificate)
        {
            // Remember the thumbprint so Dispose can locate and remove exactly this certificate.
            _thumbprint = certificate.Thumbprint;
            CertificateAccess.AddToStore(certificate, TestStoreName, TestStoreLocation);
        }

        /// <summary>
        /// Removes the certificate from the store, restoring it to its original state.
        /// </summary>
        public void Dispose()
        {
            // RemoveFromStore is a no-op if the certificate is already gone, so Dispose is safe to
            // call unconditionally.
            CertificateAccess.RemoveFromStore(_thumbprint, TestStoreName, TestStoreLocation);
        }
    }

    #endregion
}
