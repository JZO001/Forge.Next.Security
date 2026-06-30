using ErrorOr;
using Forge.Next.Shared;
using System.Security.Cryptography.X509Certificates;

namespace Forge.Next.Security;

/// <summary>
/// Provides methods for accessing and managing certificates in the certificate store.
/// </summary>
public static class CertificateAccess
{

    /// <summary>Gets the certificate from store by thumbprint.</summary>
    /// <param name="storeName">Name of the store.</param>
    /// <param name="storeLocation">The store location.</param>
    /// <param name="thumbprint">The thumbprint.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<X509Certificate2> FindByThumbprint(
        StoreName storeName,
        StoreLocation storeLocation,
        string thumbprint)
    {
        return typeof(CertificateAccess)
            .Protect<Type, X509Certificate2>(_ =>
            {
                using X509Store store = new(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection certificates = store
                    .Certificates
                    .Find(X509FindType.FindByThumbprint, thumbprint, false);

                return certificates.Count > 0 ? certificates[0] : Error.NotFound();
            });
    }

    /// <summary>Gets all certificates from store.</summary>
    /// <param name="storeName">Name of the store.</param>
    /// <param name="storeLocation">The store location.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<IEnumerable<X509Certificate2>> GetAllFromStore(
        StoreName storeName,
        StoreLocation storeLocation)
    {
        return typeof(CertificateAccess)
            .Protect<Type, IEnumerable<X509Certificate2>>(_ =>
            {
                using X509Store store = new(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                return store
                    .Certificates
                    .Select(x => x)
                    .ToList();
            });
    }

    /// <summary>Finds the certificates by DNS names.</summary>
    /// <param name="storeName">Name of the store.</param>
    /// <param name="storeLocation">The store location.</param>
    /// <param name="dnsEntries">The DNS entries.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<IEnumerable<X509Certificate2>> FindByDnsNames(
        StoreName storeName,
        StoreLocation storeLocation,
        IEnumerable<string> dnsEntries)
    {
        return typeof(CertificateAccess)
            .Protect<Type, IEnumerable<X509Certificate2>>(_ =>
            {
                using X509Store store = new(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                List<X509Certificate2> certs = [];

                foreach (X509Certificate2 cert in store.Certificates)
                {
                    ErrorOr<bool> result = GetAlternateNames(cert)
                        .Then(names => names.Select(x => x.ToLowerInvariant()))
                        .ThenDo(dnsNamesInCert => dnsEntries = dnsEntries.Select(x => x.ToLowerInvariant()))
                        .Then(dnsNamesInCert => dnsEntries.All(dns => dnsNamesInCert.Contains(dns)));

                    if (result.IsError) return result.Errors;

                    if (result.Value) certs.Add(cert);
                }

                return certs;
            });
    }

    /// <summary>Gets the certificate alternate names.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>
    /// </returns>
    public static ErrorOr<IEnumerable<string>> GetAlternateNames(X509Certificate2 certificate)
    {
        return typeof(CertificateAccess)
            .Protect<Type, IEnumerable<string>>(_ =>
            {
                List<string> dnsNames = new();

                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension is X509SubjectAlternativeNameExtension sanExtension)
                    {
                        dnsNames.AddRange(sanExtension.EnumerateIPAddresses().Select(ip => ip.ToString()));
                        dnsNames.AddRange(sanExtension.EnumerateDnsNames());
                    }
                }

                return dnsNames;
            });
    }

    /// <summary>Adds the certificate to store.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="storeName">Name of the store.</param>
    /// <param name="storeLocation">The store location.</param>
    public static ErrorOr<Success> AddToStore(
        X509Certificate2 certificate,
        StoreName storeName,
        StoreLocation storeLocation)
    {
        return typeof(CertificateAccess)
            .Protect<Type, Success>(_ =>
            {
                using X509Store store = new(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);
                store.Add(certificate);

                return Result.Success;
            });
    }

    /// <summary>Removes the certificate from store.</summary>
    /// <param name="thumbprint">The thumbprint.</param>
    /// <param name="storeName">Name of the store.</param>
    /// <param name="storeLocation">The store location.</param>
    public static ErrorOr<Success> RemoveFromStore(
        string thumbprint,
        StoreName storeName,
        StoreLocation storeLocation)
    {
        return typeof(CertificateAccess)
            .Protect<Type, Success>(_ =>
            {
                using X509Store store = new(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);

                X509Certificate2Collection certificates = store
                    .Certificates
                    .Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certificates.Count > 0)
                {
                    store.Remove(certificates[0]);
                }

                return Result.Success;
            });
    }

}
