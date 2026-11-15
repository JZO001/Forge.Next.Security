using ErrorOr;
using Forge.Next.Shared;
using System.Globalization;
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

    // The authenticated format of AesGcmEncrypt and AesGcmDecrypt:
    //   v2:<iterations>:<Base64 salt>:<Base64 nonce>:<Base64 ciphertext followed by the tag>
    // The key is PBKDF2-HMAC-SHA256 of the UTF-8 password with the salt; the cipher is AES-256-GCM, and the associated
    // data is the UTF-8 text before the last colon, so the version, the iterations, the salt and the nonce are
    // authenticated with the ciphertext. A payload of AesEncrypt starts with a 24-character Base64 IV, which never holds
    // a colon, so the prefix "v2:" tells the formats apart; "v2" alone would not.

    /// <summary>The prefix of a payload in the authenticated format, colon included.</summary>
    private const string GcmPrefix = "v2:";

    /// <summary>
    /// The PBKDF2 iteration count of <see cref="AesGcmEncrypt"/> when the caller passes none. Private and applied at run
    /// time, so a later raise reaches the callers without a recompile; the payload records the count it was made with.
    /// </summary>
    private const int GcmDefaultIterations = 600_000;

    /// <summary>
    /// The highest PBKDF2 iteration count accepted, ten times the default. <see cref="AesGcmDecrypt"/> checks it before
    /// it derives the key, so a payload cannot make a decryption run an unbounded number of iterations.
    /// </summary>
    private const int GcmMaxIterations = 6_000_000;

    private const int GcmSaltSize = 16;
    private const int GcmNonceSize = 12;
    private const int GcmTagSize = 16;
    private const int GcmKeySize = 32;

    private static readonly Error GcmInvalidPayload = Error.Validation(
        code: "AesGcm.InvalidPayload",
        description: "The content is not a valid AES-GCM payload.");

    private static readonly Error GcmAuthenticationFailed = Error.Failure(
        code: "AesGcm.AuthenticationFailed",
        description: "The payload failed authentication: a wrong password or a changed payload.");

    private static readonly Error GcmNotSupported = Error.Failure(
        code: "AesGcm.NotSupported",
        description: "AES-GCM is not supported on this platform.");

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
    /// <remarks>
    /// The payload is AES-CBC without integrity protection. New data should use <see cref="AesGcmEncrypt"/>;
    /// <see cref="AesDecrypt"/> reads both formats.
    /// </remarks>
    [Obsolete("AesEncrypt writes AES-CBC payloads without integrity protection. Use AesGcmEncrypt; AesDecrypt reads both formats.")]
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
    /// Reads both formats: a payload of <see cref="AesEncrypt"/>, and a payload of <see cref="AesGcmEncrypt"/>
    /// (it starts with <c>v2:</c>), which it decrypts with <see cref="AesGcmDecrypt"/>.
    /// </summary>
    /// <param name="password">The password to derive the AES key from.</param>
    /// <param name="encryptedContent">The content to decrypt.</param>
    /// <param name="hashAlgorithmName">The hash algorithm to use in PBKDF2. Default is HashAlgorithmName.SHA256.
    /// Ignored for a payload of <see cref="AesGcmEncrypt"/>, which records its own parameters.</param>
    /// <param name="outputLength">The desired length of the derived key. Ignored for a payload of
    /// <see cref="AesGcmEncrypt"/>.</param>
    /// <param name="iterations">The number of iterations to use in the key derivation. Ignored for a payload of
    /// <see cref="AesGcmEncrypt"/>.</param>
    /// <returns>The decrypted content as a string; the input unchanged when it cannot be decrypted, in either format.</returns>
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

        if (encryptedContent.StartsWith(GcmPrefix, StringComparison.Ordinal))
            return AesGcmDecrypt(password, encryptedContent)
                .Else(_ => encryptedContent);

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

    /// <summary>
    /// Encrypts the given content with AES-256-GCM, with a key derived from the password by PBKDF2-HMAC-SHA256, into an
    /// authenticated payload: <c>v2:&lt;iterations&gt;:&lt;Base64 salt&gt;:&lt;Base64 nonce&gt;:&lt;Base64 ciphertext
    /// followed by the tag&gt;</c>. The salt (16 bytes) and the nonce (12 bytes) are random for every call; the version,
    /// the iterations, the salt and the nonce are authenticated with the ciphertext.
    /// </summary>
    /// <param name="password">The password to derive the AES key from.</param>
    /// <param name="content">The content to encrypt. Empty and whitespace-only content is encrypted as well, and
    /// <see cref="AesGcmDecrypt"/> gives it back exactly.</param>
    /// <param name="iterations">The PBKDF2 iteration count, recorded in the payload: from 1 to 6,000,000. <c>null</c>
    /// takes the library's current default (600,000), applied at run time.</param>
    /// <returns>The payload; a <see cref="ErrorType.Validation"/> error for a null <paramref name="password"/> or
    /// <paramref name="content"/>, or an iteration count out of range (the description names the parameter); a
    /// <see cref="ErrorType.Failure"/> error (<c>AesGcm.NotSupported</c>) where the platform has no AES-GCM.</returns>
    public static ErrorOr<string> AesGcmEncrypt(string password, string content, int? iterations = null)
    {
        if (password is null) return Error.Validation(description: nameof(password));
        if (content is null) return Error.Validation(description: nameof(content));

        int iterationCount = iterations ?? GcmDefaultIterations;
        if (iterationCount < 1 || iterationCount > GcmMaxIterations) return Error.Validation(description: nameof(iterations));

        if (!AesGcm.IsSupported) return GcmNotSupported;

        return typeof(AesCryptography)
            .Protect<Type, string>(_ =>
            {
                byte[] salt = RandomNumberGenerator.GetBytes(GcmSaltSize);
                byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
                string header = string.Join(
                    ':',
                    "v2",
                    iterationCount.ToString(CultureInfo.InvariantCulture),
                    Convert.ToBase64String(salt),
                    Convert.ToBase64String(nonce));

                byte[] plaintext = Encoding.UTF8.GetBytes(content);
                byte[] sealedData = new byte[plaintext.Length + GcmTagSize];
                byte[] key = DeriveGcmKey(password, salt, iterationCount);

                try
                {
                    using AesGcm aesGcm = new AesGcm(key, GcmTagSize);
                    aesGcm.Encrypt(
                        nonce,
                        plaintext,
                        sealedData.AsSpan(0, plaintext.Length),
                        sealedData.AsSpan(plaintext.Length),
                        Encoding.UTF8.GetBytes(header));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                    CryptographicOperations.ZeroMemory(plaintext);
                }

                return $"{header}:{Convert.ToBase64String(sealedData)}";
            });
    }

    /// <summary>
    /// Decrypts a payload of <see cref="AesGcmEncrypt"/>. Unlike <see cref="AesDecrypt"/>, it reports a failure as an
    /// error instead of handing the input back.
    /// </summary>
    /// <param name="password">The password to derive the AES key from.</param>
    /// <param name="encryptedContent">The payload to decrypt.</param>
    /// <returns>The decrypted content; a <see cref="ErrorType.Validation"/> error for a null argument (the description
    /// names the parameter), or for content that is not a valid payload (<c>AesGcm.InvalidPayload</c>: not the
    /// <c>v2:</c> format, Base64 or lengths that do not fit, or an iteration count outside 1 to 6,000,000, checked
    /// before the key is derived); a <see cref="ErrorType.Failure"/> error when the payload fails authentication
    /// (<c>AesGcm.AuthenticationFailed</c>: a wrong password or a changed payload), or where the platform has no AES-GCM
    /// (<c>AesGcm.NotSupported</c>). No error carries the password, the key or any part of the plaintext.</returns>
    public static ErrorOr<string> AesGcmDecrypt(string password, string encryptedContent)
    {
        if (password is null) return Error.Validation(description: nameof(password));
        if (encryptedContent is null) return Error.Validation(description: nameof(encryptedContent));

        if (!AesGcm.IsSupported) return GcmNotSupported;

        return typeof(AesCryptography)
            .Protect<Type, string>(_ =>
            {
                if (!TryParseGcmPayload(
                        encryptedContent,
                        out string header,
                        out int iterationCount,
                        out byte[] salt,
                        out byte[] nonce,
                        out byte[] sealedData))
                {
                    return GcmInvalidPayload;
                }

                int ciphertextLength = sealedData.Length - GcmTagSize;
                byte[] plaintext = new byte[ciphertextLength];
                byte[] key = DeriveGcmKey(password, salt, iterationCount);

                try
                {
                    using AesGcm aesGcm = new AesGcm(key, GcmTagSize);
                    aesGcm.Decrypt(
                        nonce,
                        sealedData.AsSpan(0, ciphertextLength),
                        sealedData.AsSpan(ciphertextLength),
                        plaintext,
                        Encoding.UTF8.GetBytes(header));
                }
                catch (AuthenticationTagMismatchException)
                {
                    return GcmAuthenticationFailed;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }

                return Encoding.UTF8.GetString(plaintext);
            });
    }

    private static byte[] DeriveGcmKey(string password, byte[] salt, int iterationCount)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterationCount,
            HashAlgorithmName.SHA256,
            GcmKeySize);
    }

    private static bool TryParseGcmPayload(
        string payload,
        out string header,
        out int iterationCount,
        out byte[] salt,
        out byte[] nonce,
        out byte[] sealedData)
    {
        header = string.Empty;
        iterationCount = 0;
        salt = nonce = sealedData = Array.Empty<byte>();

        if (!payload.StartsWith(GcmPrefix, StringComparison.Ordinal)) return false;

        string[] parts = payload.Split(':');
        if (parts.Length != 5) return false;

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterationCount)) return false;
        if (iterationCount < 1 || iterationCount > GcmMaxIterations) return false;

        byte[]? saltBytes = DecodeBase64(parts[2]);
        byte[]? nonceBytes = DecodeBase64(parts[3]);
        byte[]? sealedBytes = DecodeBase64(parts[4]);
        if (saltBytes is null || saltBytes.Length != GcmSaltSize) return false;
        if (nonceBytes is null || nonceBytes.Length != GcmNonceSize) return false;
        if (sealedBytes is null || sealedBytes.Length < GcmTagSize) return false;

        header = payload.Substring(0, payload.LastIndexOf(':'));
        salt = saltBytes;
        nonce = nonceBytes;
        sealedData = sealedBytes;
        return true;
    }

    private static byte[]? DecodeBase64(string text)
    {
        byte[] buffer = new byte[(text.Length * 3 / 4) + 3];
        return Convert.TryFromBase64String(text, buffer, out int written)
            ? buffer.AsSpan(0, written).ToArray()
            : null;
    }

}
