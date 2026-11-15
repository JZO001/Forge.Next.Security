using ErrorOr;
using Forge.Next.Shared;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Forge.Next.Security;

/// <summary>
/// Provides methods for creating and managing self-signed certificates.
/// </summary>
public static class CertificateFactory
{

    /// <summary>
    /// The localhost DNS name.
    /// </summary>
    public const string Localhost = "localhost";

    /// <summary>
    /// The storage flags of every PFX load (the password overload of <c>CreateSelfSigned</c>, <c>GetFromRawData</c>,
    /// <c>GetFromFile</c>) unless the caller passes others. The key is persisted because SChannel, the TLS stack of
    /// Windows, needs a persisted key for a server certificate; an ephemeral one fails the handshake.
    /// </summary>
    private const X509KeyStorageFlags PfxKeyStorageFlags =
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet;

    #region CreateSelfSigned

    /// <summary>Creates the self sign certificate with MachineKeySet</summary>
    /// <param name="x500">The X500.</param>
    /// <param name="friendlyName">The friendly name.</param>
    /// <param name="dnsNames">The DNS names.</param>
    /// <param name="startTime">The start time.</param>
    /// <param name="endTime">The end time.</param>
    /// <param name="password">The insecure password.</param>
    /// <param name="keySize">Size of the key.</param>
    /// <param name="keyStorageFlags">The storage flags of the PFX load. The default,
    /// <c>Exportable | PersistKeySet | MachineKeySet</c>, persists the private key in the machine key store, where it stays
    /// until it is deleted; <see cref="X509KeyStorageFlags.EphemeralKeySet"/> keeps it in memory.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<X509Certificate2> CreateSelfSigned(
        string x500,
        string friendlyName,
        IEnumerable<string> dnsNames,
        DateTime startTime,
        DateTime endTime,
        string password,
        int keySize = 2048,
        X509KeyStorageFlags keyStorageFlags = PfxKeyStorageFlags)
    {
        return CreateSelfSigned(x500, friendlyName, dnsNames, startTime, endTime, keySize)
            .Then(certificate => ExportToPfxRawData(certificate, password))
            .Then(pfxData => GetFromRawData(pfxData, password, keyStorageFlags));
    }

    /// <summary>
    /// Creates the self sign certificate PFX.
    /// </summary>
    /// <param name="x500">The X500 subject.</param>
    /// <param name="friendlyName">The friendly name.</param>
    /// <param name="dnsNames">The DNS names.</param>
    /// <param name="startTime">The start time.</param>
    /// <param name="endTime">The end time.</param>
    /// <param name="keySize">Size of the key.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentException">
    /// </exception>
    public static ErrorOr<X509Certificate2> CreateSelfSigned(
        string x500,
        string friendlyName,
        IEnumerable<string> dnsNames,
        DateTime startTime,
        DateTime endTime,
        int keySize = 2048)
    {
        return typeof(CertificateFactory)
            .Protect<Type, X509Certificate2>(_ =>
            {
                string subject = x500 ?? string.Empty;
                SubjectAlternativeNameBuilder sanBuilder = BuildSanBuilder(dnsNames);
                X500DistinguishedName distinguishedName = new X500DistinguishedName(subject);

                using RSA rsa = RSA.Create(keySize);
                CertificateRequest request = BuildCertificateRequest(distinguishedName, rsa, sanBuilder);

                X509Certificate2 certificate = request.CreateSelfSigned(
                    ToUtcDateTimeOffset(startTime, TimeZoneInfo.Local),
                    ToUtcDateTimeOffset(endTime, TimeZoneInfo.Local));

                ApplyWindowsFriendlyName(certificate, friendlyName);

                return certificate;
            });
    }

    /// <summary>
    /// Converts a validity time to a UTC <see cref="DateTimeOffset"/> as <c>new DateTimeOffset(time)</c> does (a time
    /// whose kind is not UTC is local time in <paramref name="zone"/>), but clamps a result beyond the range of
    /// <see cref="DateTime"/> instead of throwing: a local <see cref="DateTime.MaxValue"/> west of UTC, or a local
    /// <see cref="DateTime.MinValue"/> east of it. Every time within the range converts as before.
    /// </summary>
    /// <param name="time">The time to convert.</param>
    /// <param name="zone">The local time zone: <see cref="TimeZoneInfo.Local"/>, or another one in the tests.</param>
    /// <returns>The time in UTC (offset zero).</returns>
    internal static DateTimeOffset ToUtcDateTimeOffset(DateTime time, TimeZoneInfo zone)
    {
        // GetUtcOffset, not ConvertTimeToUtc: the latter throws for a time that the daylight-saving switch skips, while
        // the DateTimeOffset constructor this replaces does not.
        TimeSpan offset = time.Kind == DateTimeKind.Utc ? TimeSpan.Zero : zone.GetUtcOffset(time);
        long utcTicks = Math.Clamp(time.Ticks - offset.Ticks, DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks);

        return new DateTimeOffset(utcTicks, TimeSpan.Zero);
    }

    private static SubjectAlternativeNameBuilder BuildSanBuilder(IEnumerable<string> dnsNames)
    {
        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();

        foreach (string dnsName in dnsNames)
        {
            AppendCustomDnsName(sanBuilder, dnsName);
        }

        AppendDefaultSanEntries(sanBuilder);

        return sanBuilder;
    }

    private static void AppendCustomDnsName(SubjectAlternativeNameBuilder sanBuilder, string dnsName)
    {
        if (IPAddress.TryParse(dnsName, out IPAddress? ipAddress))
        {
            if (IsLoopbackIpAddress(ipAddress)) return;
            sanBuilder.AddIpAddress(ipAddress);
            return;
        }

        if (IsReservedDnsName(dnsName)) return;

        sanBuilder.AddDnsName(dnsName);
    }

    private static bool IsLoopbackIpAddress(IPAddress ipAddress)
    {
        return IPAddress.Loopback.Equals(ipAddress)
            || IPAddress.IPv6Loopback.Equals(ipAddress);
    }

    private static bool IsReservedDnsName(string dnsName)
    {
        return string.Equals(Localhost, dnsName, StringComparison.OrdinalIgnoreCase)
            || string.Equals("*", dnsName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(Environment.MachineName, dnsName, StringComparison.OrdinalIgnoreCase);
    }

    private static void AppendDefaultSanEntries(SubjectAlternativeNameBuilder sanBuilder)
    {
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
        sanBuilder.AddIpAddress(IPAddress.Parse("0.0.0.0"));
        sanBuilder.AddIpAddress(IPAddress.IPv6Any);
        sanBuilder.AddIpAddress(IPAddress.Any);
        sanBuilder.AddDnsName(Localhost);
        sanBuilder.AddDnsName(Environment.MachineName);
    }

    private static CertificateRequest BuildCertificateRequest(
        X500DistinguishedName distinguishedName,
        RSA rsa,
        SubjectAlternativeNameBuilder sanBuilder)
    {
        CertificateRequest request = new(
            distinguishedName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                false));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                false));

        request.CertificateExtensions.Add(sanBuilder.Build());

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));

        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request;
    }

    private static void ApplyWindowsFriendlyName(X509Certificate2 certificate, string friendlyName)
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT) return;

#pragma warning disable CA1416 // Validate platform compatibility
        certificate.FriendlyName = friendlyName;
#pragma warning restore CA1416 // Validate platform compatibility
    }

    #endregion

    /// <summary>Exports to PFX raw data. On <c>net10.0</c> and later the PFX is protected with PBES2, AES-256 and
    /// SHA-256; on <c>net8.0</c> and <c>net9.0</c>, which have no <c>ExportPkcs12</c>, with the legacy TripleDES and
    /// SHA-1 of <see cref="X509Certificate.Export(X509ContentType, string)"/>.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="password">The password.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<byte[]> ExportToPfxRawData(X509Certificate2 certificate, string password)
        => certificate
            .Protect<X509Certificate2, byte[]>(_ =>
#if NET10_0_OR_GREATER
                certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password)
#else
                certificate.Export(X509ContentType.Pfx, password)
#endif
            );

    /// <summary>Exports to cer file.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<byte[]> ExportToCerFile(X509Certificate2 certificate)
        => certificate
            .Protect<X509Certificate2, byte[]>(_ => certificate.Export(X509ContentType.Cert));

    /// <summary>Gets the certificate for localhost, valid from a day ago to 9999-12-31 23:59:59 UTC in every time
    /// zone.</summary>
    /// <param name="subject">The subject name for the certificate. CN=your company</param>
    /// <param name="friendlyName">The friendly name for the certificate.</param>
    /// <param name="keySize">The size of the key.</param>
    /// <returns></returns>
    public static ErrorOr<X509Certificate2> GetForLocalhost(string subject, string friendlyName, int keySize = 2048)
    {
        return CreateSelfSigned(
            subject,
            friendlyName,
            Array.Empty<string>(),
            DateTime.UtcNow.AddDays(-1),
            DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc),
            keySize);
    }

    /// <summary>Gets the certificate from raw data.</summary>
    /// <param name="certificateData">The certificate data.</param>
    /// <param name="password">The password.</param>
    /// <param name="keyStorageFlags">The storage flags of the load. The default,
    /// <c>Exportable | PersistKeySet | MachineKeySet</c>, persists the private key in the machine key store, where it stays
    /// until it is deleted; <see cref="X509KeyStorageFlags.EphemeralKeySet"/> keeps it in memory.</param>
    /// <returns></returns>
    public static ErrorOr<X509Certificate2> GetFromRawData(
        byte[] certificateData,
        string password,
        X509KeyStorageFlags keyStorageFlags = PfxKeyStorageFlags)
    {
        return typeof(CertificateFactory)
            .Protect<Type, X509Certificate2>(_ =>
#if NET8_0
                new X509Certificate2(certificateData, password, keyStorageFlags)
#else
                X509CertificateLoader.LoadPkcs12(certificateData, password, keyStorageFlags)
#endif
            );
    }

    /// <summary>Gets the certificate from file.</summary>
    /// <param name="certificateFile">The certificate file.</param>
    /// <param name="password">The password.</param>
    /// <param name="keyStorageFlags">The storage flags of the load. The default,
    /// <c>Exportable | PersistKeySet | MachineKeySet</c>, persists the private key in the machine key store, where it stays
    /// until it is deleted; <see cref="X509KeyStorageFlags.EphemeralKeySet"/> keeps it in memory.</param>
    /// <returns></returns>
    public static ErrorOr<X509Certificate2> GetFromFile(
        string certificateFile,
        string? password,
        X509KeyStorageFlags keyStorageFlags = PfxKeyStorageFlags)
    {
        return typeof(CertificateFactory)
            .Protect<Type, X509Certificate2>(_ =>
#if NET8_0
                new X509Certificate2(certificateFile, password, keyStorageFlags)
#else
                X509CertificateLoader.LoadPkcs12FromFile(certificateFile, password, keyStorageFlags)
#endif
            );
    }

}
