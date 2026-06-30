using ErrorOr;
using System.Security.Cryptography;
using Shouldly;
using Xunit;

namespace Forge.Next.Security.Tests;

/// <summary>
/// Unit tests for <see cref="AesCryptography"/>.
///
/// <para>
/// <see cref="AesCryptography"/> is a <c>static</c> helper that derives AES keys with PBKDF2 and
/// performs AES-CBC encryption/decryption. It has no injectable collaborators, so there is nothing
/// for a mocking library such as NSubstitute to substitute: the tests exercise the real
/// <see cref="System.Security.Cryptography"/> primitives end-to-end.
/// </para>
///
/// <para>
/// Every public method returns an <see cref="ErrorOr{TValue}"/>. Argument validation produces an
/// <see cref="ErrorType.Validation"/> error (with the offending parameter name as the description),
/// while the work itself is wrapped in the <c>Protect</c> helper from <c>Forge.Next.Shared</c>
/// (which converts thrown exceptions into errors). Note that <see cref="AesCryptography.AesDecrypt"/>
/// finishes with an <c>.Else(...)</c> that maps any internal failure back to the original input, so
/// for non-null passwords it always yields a successful value. Tests assert on
/// <see cref="ErrorOr{TValue}.IsError"/> / <see cref="ErrorOr{TValue}.Value"/> /
/// <see cref="ErrorOr{TValue}.FirstError"/> accordingly.
/// </para>
/// </summary>
public class AesCryptographyTests
{
    // ---------------------------------------------------------------------------------------------
    // Shared test data. Centralising these keeps each test focused on the behaviour under test.
    // ---------------------------------------------------------------------------------------------

    /// <summary>A representative password used across the tests.</summary>
    private const string Password = "correct horse battery staple";

    /// <summary>A representative salt used for the key-derivation tests.</summary>
    private const string Salt = "a-pinch-of-salt";

    /// <summary>A representative plaintext used for the encrypt/decrypt round-trips.</summary>
    private const string PlainText = "The quick brown fox jumps over the lazy dog.";

    #region MakeAESKey

    /// <summary>
    /// Deriving a key from a password and salt must succeed and, by default, produce a 32-byte
    /// (256-bit) key suitable for AES-256.
    /// </summary>
    [Fact]
    public void MakeAESKeyTest()
    {
        // Act.
        ErrorOr<byte[]> result = AesCryptography.MakeAESKey(Password, Salt);

        // Assert: success and the default output length of 32 bytes.
        result.IsError.ShouldBeFalse();
        result.Value.Length.ShouldBe(32);
    }

    /// <summary>
    /// PBKDF2 is deterministic: the same password, salt, hash algorithm, output length and iteration
    /// count must always yield the exact same key bytes.
    /// </summary>
    [Fact]
    public void MakeAESKey_IsDeterministic_Test()
    {
        // Act: derive the key twice with identical inputs.
        ErrorOr<byte[]> first = AesCryptography.MakeAESKey(Password, Salt);
        ErrorOr<byte[]> second = AesCryptography.MakeAESKey(Password, Salt);

        first.IsError.ShouldBeFalse();
        second.IsError.ShouldBeFalse();

        // Assert: the two derivations are byte-for-byte identical (Shouldly compares sequences).
        first.Value.ShouldBe(second.Value);
    }

    /// <summary>
    /// Changing only the salt must change the derived key — this is the whole point of a salt.
    /// </summary>
    [Fact]
    public void MakeAESKey_DifferentSaltProducesDifferentKey_Test()
    {
        // Act.
        ErrorOr<byte[]> key1 = AesCryptography.MakeAESKey(Password, "salt-one");
        ErrorOr<byte[]> key2 = AesCryptography.MakeAESKey(Password, "salt-two");

        key1.IsError.ShouldBeFalse();
        key2.IsError.ShouldBeFalse();

        // Assert: different salts produce different keys.
        key1.Value.ShouldNotBe(key2.Value);
    }

    /// <summary>
    /// Changing only the password must change the derived key.
    /// </summary>
    [Fact]
    public void MakeAESKey_DifferentPasswordProducesDifferentKey_Test()
    {
        // Act.
        ErrorOr<byte[]> key1 = AesCryptography.MakeAESKey("password-one", Salt);
        ErrorOr<byte[]> key2 = AesCryptography.MakeAESKey("password-two", Salt);

        key1.IsError.ShouldBeFalse();
        key2.IsError.ShouldBeFalse();

        // Assert: different passwords produce different keys.
        key1.Value.ShouldNotBe(key2.Value);
    }

    /// <summary>
    /// The caller-supplied output length must be honoured (here 16 bytes / 128 bits).
    /// </summary>
    [Fact]
    public void MakeAESKey_RespectsOutputLength_Test()
    {
        // Act: request a 16-byte key (the hash algorithm argument is left at its default of null).
        ErrorOr<byte[]> result = AesCryptography.MakeAESKey(Password, Salt, hashAlgorithmName: null, outputLength: 16);

        // Assert: the derived key has exactly the requested length.
        result.IsError.ShouldBeFalse();
        result.Value.Length.ShouldBe(16);
    }

    /// <summary>
    /// Changing only the PBKDF2 hash algorithm must change the derived key.
    /// </summary>
    [Fact]
    public void MakeAESKey_DifferentHashAlgorithmProducesDifferentKey_Test()
    {
        // Act: derive with SHA-256 (the default) and then explicitly with SHA-512.
        ErrorOr<byte[]> sha256 = AesCryptography.MakeAESKey(Password, Salt, HashAlgorithmName.SHA256);
        ErrorOr<byte[]> sha512 = AesCryptography.MakeAESKey(Password, Salt, HashAlgorithmName.SHA512);

        sha256.IsError.ShouldBeFalse();
        sha512.IsError.ShouldBeFalse();

        // Assert: a different PRF yields a different key (both still the default 32 bytes long).
        sha256.Value.ShouldNotBe(sha512.Value);
    }

    /// <summary>
    /// Changing only the iteration count must change the derived key.
    /// </summary>
    [Fact]
    public void MakeAESKey_DifferentIterationsProducesDifferentKey_Test()
    {
        // Act: the trailing arguments are (hashAlgorithmName, outputLength, iterations); vary only
        // the iteration count.
        ErrorOr<byte[]> few = AesCryptography.MakeAESKey(Password, Salt, null, 32, 1000);
        ErrorOr<byte[]> many = AesCryptography.MakeAESKey(Password, Salt, null, 32, 2000);

        few.IsError.ShouldBeFalse();
        many.IsError.ShouldBeFalse();

        // Assert: different iteration counts produce different keys.
        few.Value.ShouldNotBe(many.Value);
    }

    /// <summary>
    /// A <c>null</c> password must short-circuit to a <see cref="ErrorType.Validation"/> error whose
    /// description names the offending parameter.
    /// </summary>
    [Fact]
    public void MakeAESKey_NullPasswordReturnsValidationError_Test()
    {
        // Act.
        ErrorOr<byte[]> result = AesCryptography.MakeAESKey(null!, Salt);

        // Assert: validation error attributed to "password".
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Validation);
        result.FirstError.Description.ShouldBe("password");
    }

    /// <summary>
    /// A <c>null</c> salt must short-circuit to a <see cref="ErrorType.Validation"/> error whose
    /// description names the offending parameter.
    /// </summary>
    [Fact]
    public void MakeAESKey_NullSaltReturnsValidationError_Test()
    {
        // Act.
        ErrorOr<byte[]> result = AesCryptography.MakeAESKey(Password, null!);

        // Assert: validation error attributed to "salt".
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Validation);
        result.FirstError.Description.ShouldBe("salt");
    }

    #endregion

    #region AesEncrypt

    /// <summary>
    /// Encrypting content must succeed and yield a "&lt;base64 IV&gt;:&lt;base64 ciphertext&gt;"
    /// string: two non-empty, base64-decodable parts separated by a single colon, with a 16-byte IV.
    /// </summary>
    [Fact]
    public void AesEncryptTest()
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesEncrypt(Password, PlainText);

        // Assert: success.
        result.IsError.ShouldBeFalse();

        // The payload is "IV:ciphertext" — exactly two colon-separated segments.
        string[] parts = result.Value.Split(':');
        parts.Length.ShouldBe(2);

        // Both segments must be valid base64 (Convert.FromBase64String throws on malformed input).
        byte[] iv = Convert.FromBase64String(parts[0]);
        byte[] cipher = Convert.FromBase64String(parts[1]);

        // The IV of an AES block cipher is 16 bytes; the ciphertext must be non-empty.
        iv.Length.ShouldBe(16);
        cipher.Length.ShouldBeGreaterThan(0);
    }

    /// <summary>
    /// Empty or whitespace content is treated as "nothing to encrypt" and returns an empty string
    /// (a successful result, not an error).
    /// </summary>
    [Fact]
    public void AesEncrypt_EmptyContentReturnsEmpty_Test()
    {
        // Act: both an empty string and a whitespace-only string take the short-circuit path.
        ErrorOr<string> empty = AesCryptography.AesEncrypt(Password, string.Empty);
        ErrorOr<string> whitespace = AesCryptography.AesEncrypt(Password, "   ");

        // Assert: success with an empty payload in both cases.
        empty.IsError.ShouldBeFalse();
        empty.Value.ShouldBe(string.Empty);

        whitespace.IsError.ShouldBeFalse();
        whitespace.Value.ShouldBe(string.Empty);
    }

    /// <summary>
    /// A <c>null</c> password must produce a <see cref="ErrorType.Validation"/> error.
    /// </summary>
    [Fact]
    public void AesEncrypt_NullPasswordReturnsValidationError_Test()
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesEncrypt(null!, PlainText);

        // Assert.
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Validation);
        result.FirstError.Description.ShouldBe("password");
    }

    /// <summary>
    /// A fresh random IV is generated on every call, so encrypting the same content twice must yield
    /// two different payloads — a basic but important property of the construction.
    /// </summary>
    [Fact]
    public void AesEncrypt_ProducesDifferentCiphertextEachCall_Test()
    {
        // Act: encrypt identical inputs twice.
        ErrorOr<string> first = AesCryptography.AesEncrypt(Password, PlainText);
        ErrorOr<string> second = AesCryptography.AesEncrypt(Password, PlainText);

        first.IsError.ShouldBeFalse();
        second.IsError.ShouldBeFalse();

        // Assert: the random IV makes the two payloads differ.
        first.Value.ShouldNotBe(second.Value);
    }

    #endregion

    #region AesDecrypt

    /// <summary>
    /// Decrypting what was encrypted with the same password must recover the original plaintext
    /// exactly (the fundamental round-trip property).
    /// </summary>
    [Fact]
    public void AesDecryptTest()
    {
        // Arrange: produce a ciphertext payload.
        string encrypted = AesCryptography.AesEncrypt(Password, PlainText).Value;

        // Act: decrypt it with the same password.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, encrypted);

        // Assert: the original plaintext is recovered.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    /// <summary>
    /// Empty or whitespace input is treated as "nothing to decrypt" and returns an empty string.
    /// </summary>
    [Fact]
    public void AesDecrypt_EmptyContentReturnsEmpty_Test()
    {
        // Act.
        ErrorOr<string> empty = AesCryptography.AesDecrypt(Password, string.Empty);
        ErrorOr<string> whitespace = AesCryptography.AesDecrypt(Password, "   ");

        // Assert: success with an empty payload in both cases.
        empty.IsError.ShouldBeFalse();
        empty.Value.ShouldBe(string.Empty);

        whitespace.IsError.ShouldBeFalse();
        whitespace.Value.ShouldBe(string.Empty);
    }

    /// <summary>
    /// A <c>null</c> password must produce a <see cref="ErrorType.Validation"/> error — this is the
    /// only error path of <see cref="AesCryptography.AesDecrypt"/>, since all internal failures are
    /// mapped back to the input by the trailing <c>.Else(...)</c>.
    /// </summary>
    [Fact]
    public void AesDecrypt_NullPasswordReturnsValidationError_Test()
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesDecrypt(null!, "anything");

        // Assert.
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Validation);
        result.FirstError.Description.ShouldBe("password");
    }

    /// <summary>
    /// Input that is not in the expected "IV:ciphertext" shape (no colon, so it does not split into
    /// exactly two parts) is returned unchanged as a successful value.
    /// </summary>
    [Fact]
    public void AesDecrypt_MalformedInputReturnedUnchanged_Test()
    {
        // Arrange: a string with no ':' separator cannot split into two segments.
        const string notEncrypted = "this-is-not-an-encrypted-payload";

        // Act.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, notEncrypted);

        // Assert: success, and the original input flows straight back out.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(notEncrypted);
    }

    /// <summary>
    /// Input that has the right shape (two colon-separated parts) but whose segments are not valid
    /// base64 causes an internal exception, which the trailing <c>.Else(...)</c> maps back to the
    /// original input — exercising the failure-to-input fallback path deterministically.
    /// </summary>
    [Fact]
    public void AesDecrypt_UndecodableInputReturnedUnchanged_Test()
    {
        // Arrange: two segments, but "@@@" / "###" are not valid base64, so decoding throws.
        const string undecodable = "@@@:###";

        // Act.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, undecodable);

        // Assert: the caught failure is converted back into the original input (a successful value).
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(undecodable);
    }

    /// <summary>
    /// Decrypting a valid payload with the wrong password must not reveal the plaintext. The cipher
    /// fails to unpad/decrypt and the <c>.Else(...)</c> fallback returns the (still encrypted) input,
    /// so the recovered value is never the original secret.
    /// </summary>
    [Fact]
    public void AesDecrypt_WrongPasswordDoesNotRevealPlaintext_Test()
    {
        // Arrange: encrypt with the correct password.
        string encrypted = AesCryptography.AesEncrypt(Password, PlainText).Value;

        // Act: attempt to decrypt with a different password.
        ErrorOr<string> result = AesCryptography.AesDecrypt("the-wrong-password", encrypted);

        // Assert: the call still succeeds (errors are mapped to the input) but, crucially, the
        // plaintext is never disclosed.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldNotBe(PlainText);
    }

    /// <summary>
    /// A full round-trip using non-default key-derivation parameters (custom hash algorithm, output
    /// length and iteration count) must still recover the original plaintext, provided the same
    /// parameters are supplied to both encrypt and decrypt.
    /// </summary>
    [Fact]
    public void AesDecrypt_RoundTripWithCustomParameters_Test()
    {
        // Arrange: a non-default but internally consistent parameter set. outputLength stays at a
        // valid AES key size (32 bytes) so the derived key can be assigned to Aes.Key.
        HashAlgorithmName hash = HashAlgorithmName.SHA512;
        const int outputLength = 32;
        const int iterations = 5000;

        string encrypted = AesCryptography
            .AesEncrypt(Password, PlainText, hash, outputLength, iterations)
            .Value;

        // Act: decrypt with the identical parameters.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, encrypted, hash, outputLength, iterations);

        // Assert: the plaintext is recovered.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    #endregion
}
