using ErrorOr;
using Forge.Next.Shared;
using System.Security.Cryptography;
using System.Text;

namespace Forge.Next.Security;

/// <summary>
/// Provides methods for AES encryption and decryption.
/// </summary>
public static class AesCryptography
{

    /// <summary>
    /// The number of iterations to use in the PBKDF2 key derivation function.
    /// </summary>
    public const int Iterations = 100000;

    /// <summary>
    /// The default output length for the derived AES key in bytes (32 bytes = 256 bits).
    /// </summary>
    public const int DefaultOutputLength = 32; // 256 bits

    /// <summary>
    /// Generates an AES key from a password and salt using PBKDF2.
    /// </summary>
    /// <param name="password">The password to derive the key from.</param>
    /// <param name="salt">The salt to use in the key derivation.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use in PBKDF2. Default is HashAlgorithmName.SHA256.</param>
    /// <param name="outputLength">The desired length of the derived key.</param>
    /// <param name="iterations">The number of iterations to use in the key derivation.</param>
    /// <returns>The derived AES key.</returns>
    public static ErrorOr<byte[]> MakeAESKey(
        string password,
        string salt,
        HashAlgorithmName? hashAlgorithmName = null,
        int outputLength = DefaultOutputLength,
        int iterations = Iterations)
    {
        if (password is null) return Error.Validation(description: nameof(password));
        if (salt is null) return Error.Validation(description: nameof(salt));

        return typeof(CertificateFactory)
            .Protect<Type, byte[]>(_ =>
            {
                return Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(password),
                    Encoding.UTF8.GetBytes(salt),
                    iterations,
                    hashAlgorithmName ?? HashAlgorithmName.SHA256,
                    outputLength
                    );
            });
    }

    /// <summary>
    /// Encrypts the given content using AES encryption with a key derived from the provided password.
    /// </summary>
    /// <param name="password">The password to derive the AES key from.</param>
    /// <param name="content">The content to encrypt.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use in PBKDF2. Default is HashAlgorithmName.SHA256.</param>
    /// <param name="outputLength">The desired length of the derived key.</param>
    /// <param name="iterations">The number of iterations to use in the key derivation.</param>
    /// <returns>The encrypted content as a base64-encoded string.</returns>
    public static ErrorOr<string> AesEncrypt(
        string password,
        string content,
        HashAlgorithmName? hashAlgorithmName = null,
        int outputLength = DefaultOutputLength,
        int iterations = Iterations)
    {
        if (password is null) return Error.Validation(description: nameof(password));

        if (string.IsNullOrWhiteSpace(content))
            return string.Empty;

        return typeof(CertificateFactory)
            .Protect(_ =>
            {
                using Aes aes = Aes.Create();
                byte[] iV = aes.IV;
                string text = Convert.ToBase64String(iV);

                return MakeAESKey(password, text, hashAlgorithmName: hashAlgorithmName, outputLength: outputLength, iterations: iterations)
                    .ThenDo(key => aes.Key = key)
                    .Then(_ => $"{text}:{Convert.ToBase64String(aes.EncryptCbc(Encoding.UTF8.GetBytes(content), iV))}");
            });
    }

    /// <summary>
    /// Decrypts the given encrypted content using AES decryption with a key derived from the provided password.
    /// </summary>
    /// <param name="password">The password to derive the AES key from.</param>
    /// <param name="encryptedContent">The content to decrypt.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use in PBKDF2. Default is HashAlgorithmName.SHA256.</param>
    /// <param name="outputLength">The desired length of the derived key.</param>
    /// <param name="iterations">The number of iterations to use in the key derivation.</param>
    /// <returns>The decrypted content as a string.</returns>
    public static ErrorOr<string> AesDecrypt(
        string password,
        string encryptedContent,
        HashAlgorithmName? hashAlgorithmName = null,
        int outputLength = DefaultOutputLength,
        int iterations = Iterations)
    {
        if (password is null) return Error.Validation(description: nameof(password));

        if (string.IsNullOrWhiteSpace(encryptedContent))
            return string.Empty;

        return typeof(CertificateFactory)
            .Protect(_ =>
            {
                string[] array = encryptedContent.Split(":");
                if (array.Length != 2) return encryptedContent;
                string s = array[1];
                string text = array[0];
                byte[] iv = Convert.FromBase64String(text);
                using Aes aes = Aes.Create();

                return MakeAESKey(password, text, hashAlgorithmName: hashAlgorithmName, outputLength: outputLength, iterations: iterations)
                    .ThenDo(key => aes.Key = key)
                    .Then(_ => aes.DecryptCbc(Convert.FromBase64String(s), iv))
                    .Then(bytes => Encoding.UTF8.GetString(bytes));
            })
            .Else(_ => encryptedContent);
    }

}
