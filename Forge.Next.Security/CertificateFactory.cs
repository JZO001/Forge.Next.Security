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

    #region CreateSelfSigned

    /// <summary>Creates the self sign certificate with MachineKeySet</summary>
    /// <param name="x500">The X500.</param>
    /// <param name="friendlyName">The friendly name.</param>
    /// <param name="dnsNames">The DNS names.</param>
    /// <param name="startTime">The start time.</param>
    /// <param name="endTime">The end time.</param>
    /// <param name="password">The insecure password.</param>
    /// <param name="keySize">Size of the key.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<X509Certificate2> CreateSelfSigned(
        string x500,
        string friendlyName,
        IEnumerable<string> dnsNames,
        DateTime startTime,
        DateTime endTime,
        string password,
        int keySize = 2048)
    {
        return CreateSelfSigned(x500, friendlyName, dnsNames, startTime, endTime, keySize)
            .Then(certificate => ExportToPfxRawData(certificate, password))
            .Then(pfxData => GetFromRawData(pfxData, password));
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
                    new DateTimeOffset(startTime),
                    new DateTimeOffset(endTime));

                ApplyWindowsFriendlyName(certificate, friendlyName);

                return certificate;
            });
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

    /// <summary>Exports to PFX raw data.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="password">The password.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<byte[]> ExportToPfxRawData(X509Certificate2 certificate, string password)
        => certificate
            .Protect<X509Certificate2, byte[]>(_ => certificate.Export(X509ContentType.Pfx, password));

    /// <summary>Exports to cer file.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<byte[]> ExportToCerFile(X509Certificate2 certificate)
        => certificate
            .Protect<X509Certificate2, byte[]>(_ => certificate.Export(X509ContentType.Cert));

    /// <summary>Gets the certificate for localhost.</summary>
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
            DateTime.MaxValue,
            keySize);
    }

    /// <summary>Gets the certificate from raw data.</summary>
    /// <param name="certificateData">The certificate data.</param>
    /// <param name="password">The password.</param>
    /// <returns></returns>
    public static ErrorOr<X509Certificate2> GetFromRawData(byte[] certificateData, string password)
    {
        return typeof(CertificateFactory)
            .Protect<Type, X509Certificate2>(_ =>
#if NET8_0
                new X509Certificate2(
                    certificateData,
                    password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet)
#else
                X509CertificateLoader
                    .LoadPkcs12(
                        certificateData, 
                        password, 
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet)
#endif
            );
    }

    /// <summary>Gets the certificate from file.</summary>
    /// <param name="certificateFile">The certificate file.</param>
    /// <param name="password">The password.</param>
    /// <returns></returns>
    public static ErrorOr<X509Certificate2> GetFromFile(string certificateFile, string? password)
    {
        return typeof(CertificateFactory)
            .Protect<Type, X509Certificate2>(_ =>
#if NET8_0
                new X509Certificate2(
                    certificateFile,
                    password,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet)
#else
                X509CertificateLoader.LoadPkcs12FromFile(certificateFile, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet)
#endif
            );
    }

}
