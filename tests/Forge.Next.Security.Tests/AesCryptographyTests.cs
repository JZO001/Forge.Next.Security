using ErrorOr;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
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

    // AesEncrypt is [Obsolete] since AesGcmEncrypt came: it writes the AES-CBC format without integrity
    // protection. The tests below pin that format on purpose, as long as AesDecrypt must read it, so the
    // warning is suppressed from here to the end of the "AesDecrypt" region (and only there).
#pragma warning disable CS0618 // Type or member is obsolete

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

#pragma warning restore CS0618 // Type or member is obsolete

    #region Known-answer payloads

    // ---------------------------------------------------------------------------------------------
    // Payloads made once, on 2026-11-15, by AesEncrypt of the 3.2.0 code, and decrypted
    // independently with OpenSSL (PBKDF2 over the UTF-8 password with the IV's Base64 text as the
    // salt, then AES-256-CBC). They pin the stored format: "<Base64 IV>:<Base64 ciphertext>", the
    // IV's Base64 text as the PBKDF2 salt, and the defaults (HMAC-SHA-256, 100,000 iterations,
    // 32 bytes). Data encrypted by an earlier version must stay decryptable, and AesDecrypt would hide
    // a break by returning its input unchanged; these tests make such a change fail loudly instead.
    // Never regenerate these payloads to make a test pass: a failure here means stored data broke.
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// <see cref="PlainText"/> encrypted with <see cref="Password"/> and the default parameters.
    /// </summary>
    private const string KnownPayloadWithDefaults =
        "rJXou3Bh+t/JF2GnOutygQ==:u+PkyH2WEdKeAly1n9wVR+WAhabpgPJouEMnxS2vBfrfNq8h7hYIxCDrLcWYqeKt";

    /// <summary>
    /// <see cref="PlainText"/> encrypted with <see cref="Password"/>, SHA-512, a 32-byte key and
    /// 5,000 iterations.
    /// </summary>
    private const string KnownPayloadWithSha512And5000Iterations =
        "qRc+ZSBB2xAp1U1QTRYkPA==:jwpV83WNkQMQpSw+HV+yuBH47QKbWcgDdAmcV7rxs5T28UeNigJdZQHPbhWwitK+";

    /// <summary>
    /// A payload stored by an earlier version with the default parameters must still decrypt, with
    /// the default parameters, to its plaintext.
    /// </summary>
    [Fact]
    public void AesDecrypt_KnownPayloadWithDefaults_Test()
    {
        // Act: decrypt the stored payload with today's defaults.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, KnownPayloadWithDefaults);

        // Assert: the original plaintext, not the input handed back by the fallback.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    /// <summary>
    /// A payload stored with explicit parameters must still decrypt when the same parameters are
    /// passed again.
    /// </summary>
    [Fact]
    public void AesDecrypt_KnownPayloadWithCustomParameters_Test()
    {
        // Act: decrypt with the parameters the payload was made with.
        ErrorOr<string> result = AesCryptography.AesDecrypt(
            Password,
            KnownPayloadWithSha512And5000Iterations,
            HashAlgorithmName.SHA512,
            32,
            5000);

        // Assert: the original plaintext.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    /// <summary>
    /// The payload does not record its key-derivation parameters: decrypting a payload made with
    /// SHA-512 and 5,000 iterations with the defaults derives another key and must not give the
    /// plaintext back. For this fixed payload the padding check fails, so the input comes back
    /// unchanged (observed when the payload was made).
    /// </summary>
    [Fact]
    public void AesDecrypt_KnownPayloadNeedsItsParameters_Test()
    {
        // Act: decrypt with the defaults instead of the payload's parameters.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, KnownPayloadWithSha512And5000Iterations);

        // Assert: no plaintext; the lenient fallback hands the input back.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldNotBe(PlainText);
        result.Value.ShouldBe(KnownPayloadWithSha512And5000Iterations);
    }

    #endregion

    #region AesGcmEncrypt / AesGcmDecrypt

    // ---------------------------------------------------------------------------------------------
    // The authenticated format: "v2:<iterations>:<Base64 salt>:<Base64 nonce>:<Base64 ciphertext
    // followed by the tag>". Most tests pass iterations: 1, so PBKDF2 does not dominate the run: the
    // payload records its count, so a low count makes as valid a payload as the default.
    // ---------------------------------------------------------------------------------------------

    /// <summary>The salt part of <see cref="KnownGcmPayload"/> (16 bytes).</summary>
    private const string KnownGcmSalt = "x6y+E1gTvgk9FUjXC3GN0Q==";

    /// <summary>The nonce part of <see cref="KnownGcmPayload"/> (12 bytes).</summary>
    private const string KnownGcmNonce = "KU8evXU1lUQrsd0f";

    /// <summary>The ciphertext and tag part of <see cref="KnownGcmPayload"/>.</summary>
    private const string KnownGcmSealed =
        "/878FRsuXxxGcxNBhxTtMTosv407EcBkVkECeexxLBGTOd/wipI47bRzT7rnfVzm8czOmotCxdJhMPg2";

    /// <summary>
    /// <see cref="PlainText"/> encrypted by <see cref="AesCryptography.AesGcmEncrypt"/> with
    /// <see cref="Password"/> and 10,000 iterations, made once on 2026-11-15 and decrypted
    /// independently with Node.js (PBKDF2-HMAC-SHA256, then AES-256-GCM with the text before the last
    /// colon as the associated data). It pins the stored format; never regenerate it to make a test
    /// pass.
    /// </summary>
    private const string KnownGcmPayload =
        "v2:10000:" + KnownGcmSalt + ":" + KnownGcmNonce + ":" + KnownGcmSealed;

    /// <summary>
    /// Encrypting must yield five colon-separated parts: the version, the default iteration count
    /// (600,000), a 16-byte salt, a 12-byte nonce, and the ciphertext followed by a 16-byte tag.
    /// </summary>
    [Fact]
    public void AesGcmEncryptTest()
    {
        // Act: encrypt with the library's default iteration count.
        ErrorOr<string> result = AesCryptography.AesGcmEncrypt(Password, PlainText);

        // Assert: the format, part by part.
        result.IsError.ShouldBeFalse();
        string[] parts = result.Value.Split(':');
        parts.Length.ShouldBe(5);
        parts[0].ShouldBe("v2");
        parts[1].ShouldBe("600000");
        Convert.FromBase64String(parts[2]).Length.ShouldBe(16);
        Convert.FromBase64String(parts[3]).Length.ShouldBe(12);
        Convert.FromBase64String(parts[4]).Length.ShouldBe(Encoding.UTF8.GetByteCount(PlainText) + 16);
    }

    /// <summary>
    /// A payload made with the default iteration count must decrypt back to the plaintext.
    /// </summary>
    [Fact]
    public void AesGcmDecryptTest()
    {
        // Arrange.
        string payload = AesCryptography.AesGcmEncrypt(Password, PlainText).Value;

        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmDecrypt(Password, payload);

        // Assert.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    /// <summary>
    /// Unlike <c>AesEncrypt</c>, the authenticated format encrypts empty and whitespace-only content
    /// too, and gives it back exactly.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\r\n")]
    public void AesGcmEncrypt_EmptyAndWhitespaceContentRoundTrip_Test(string content)
    {
        // Arrange.
        string payload = AesCryptography.AesGcmEncrypt(Password, content, 1).Value;

        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmDecrypt(Password, payload);

        // Assert: the content comes back exactly, not as "".
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(content);
    }

    /// <summary>
    /// The salt and the nonce are random for every call, so the same content gives different
    /// payloads.
    /// </summary>
    [Fact]
    public void AesGcmEncrypt_ProducesDifferentPayloadEachCall_Test()
    {
        // Act.
        string first = AesCryptography.AesGcmEncrypt(Password, PlainText, 1).Value;
        string second = AesCryptography.AesGcmEncrypt(Password, PlainText, 1).Value;

        // Assert: different salt, nonce and ciphertext.
        string[] a = first.Split(':');
        string[] b = second.Split(':');
        a[2].ShouldNotBe(b[2]);
        a[3].ShouldNotBe(b[3]);
        a[4].ShouldNotBe(b[4]);
    }

    /// <summary>
    /// The iteration count passed by the caller is recorded in the payload.
    /// </summary>
    [Fact]
    public void AesGcmEncrypt_RecordsIterations_Test()
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmEncrypt(Password, PlainText, 1);

        // Assert.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldStartWith("v2:1:");
    }

    /// <summary>
    /// A null password or content must be a <see cref="ErrorType.Validation"/> error that names the
    /// parameter.
    /// </summary>
    [Fact]
    public void AesGcmEncrypt_NullArgumentsReturnValidationError_Test()
    {
        // Act.
        ErrorOr<string> nullPassword = AesCryptography.AesGcmEncrypt(null!, PlainText);
        ErrorOr<string> nullContent = AesCryptography.AesGcmEncrypt(Password, null!);

        // Assert.
        nullPassword.FirstError.Type.ShouldBe(ErrorType.Validation);
        nullPassword.FirstError.Description.ShouldBe("password");
        nullContent.FirstError.Type.ShouldBe(ErrorType.Validation);
        nullContent.FirstError.Description.ShouldBe("content");
    }

    /// <summary>
    /// An iteration count below 1 or above 6,000,000 must be a <see cref="ErrorType.Validation"/>
    /// error: the decrypt would reject such a payload.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(6_000_001)]
    public void AesGcmEncrypt_IterationsOutOfRangeReturnValidationError_Test(int iterations)
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmEncrypt(Password, PlainText, iterations);

        // Assert.
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Validation);
        result.FirstError.Description.ShouldBe("iterations");
    }

    /// <summary>
    /// A payload stored with the authenticated format must keep decrypting to its plaintext.
    /// </summary>
    [Fact]
    public void AesGcmDecrypt_KnownPayload_Test()
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmDecrypt(Password, KnownGcmPayload);

        // Assert.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    /// <summary>
    /// A null password or payload must be a <see cref="ErrorType.Validation"/> error that names the
    /// parameter.
    /// </summary>
    [Fact]
    public void AesGcmDecrypt_NullArgumentsReturnValidationError_Test()
    {
        // Act.
        ErrorOr<string> nullPassword = AesCryptography.AesGcmDecrypt(null!, KnownGcmPayload);
        ErrorOr<string> nullContent = AesCryptography.AesGcmDecrypt(Password, null!);

        // Assert.
        nullPassword.FirstError.Type.ShouldBe(ErrorType.Validation);
        nullPassword.FirstError.Description.ShouldBe("password");
        nullContent.FirstError.Type.ShouldBe(ErrorType.Validation);
        nullContent.FirstError.Description.ShouldBe("encryptedContent");
    }

    /// <summary>
    /// A change to any authenticated part of a payload (the iteration count, the salt, the nonce, the
    /// ciphertext or the tag) must fail authentication: a <see cref="ErrorType.Failure"/> error, never
    /// text.
    /// </summary>
    [Theory]
    [InlineData("iterations")]
    [InlineData("salt")]
    [InlineData("nonce")]
    [InlineData("ciphertext")]
    [InlineData("tag")]
    public void AesGcmDecrypt_ChangedPayloadFailsAuthentication_Test(string part)
    {
        // Arrange: a valid payload with one part changed.
        string payload = AesCryptography.AesGcmEncrypt(Password, PlainText, 1).Value;
        string changed = ChangeGcmPayload(payload, part);

        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmDecrypt(Password, changed);

        // Assert.
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Failure);
        result.FirstError.Code.ShouldBe("AesGcm.AuthenticationFailed");
    }

    /// <summary>
    /// A changed version marker is no longer the authenticated format: a
    /// <see cref="ErrorType.Validation"/> error (<c>AesGcm.InvalidPayload</c>), never text.
    /// </summary>
    [Fact]
    public void AesGcmDecrypt_ChangedVersionIsInvalidPayload_Test()
    {
        // Arrange: "v2:..." becomes "v3:...".
        string payload = AesCryptography.AesGcmEncrypt(Password, PlainText, 1).Value;
        string changed = "v3" + payload.Substring(2);

        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmDecrypt(Password, changed);

        // Assert.
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Validation);
        result.FirstError.Code.ShouldBe("AesGcm.InvalidPayload");
    }

    /// <summary>
    /// A wrong password must never give text: 20,000 wrong passwords (with one iteration, so the run
    /// stays short) must each fail authentication. The CBC format of <c>AesEncrypt</c> returned other
    /// text for about 0.4 % of wrong passwords.
    /// </summary>
    [Fact]
    public void AesGcmDecrypt_WrongPasswordNeverGivesText_Test()
    {
        // Arrange.
        string payload = AesCryptography.AesGcmEncrypt(Password, PlainText, 1).Value;
        int failures = 0;

        // Act: count the authentication failures.
        for (int i = 0; i < 20_000; i++)
        {
            ErrorOr<string> result = AesCryptography.AesGcmDecrypt($"wrong-{i}", payload);
            if (result.IsError && result.FirstError.Code == "AesGcm.AuthenticationFailed") failures++;
        }

        // Assert: every try failed authentication.
        failures.ShouldBe(20_000);
    }

    /// <summary>
    /// Content that is not a valid payload must be a <see cref="ErrorType.Validation"/> error
    /// (<c>AesGcm.InvalidPayload</c>). The iteration count is checked before PBKDF2 runs, so a payload
    /// cannot ask for more than 6,000,000 iterations.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("v2:")]
    [InlineData("v2:10000:" + KnownGcmSalt + ":" + KnownGcmNonce)]
    [InlineData(KnownGcmPayload + ":extra")]
    [InlineData(KnownPayloadWithDefaults)]
    [InlineData("v2:abc:" + KnownGcmSalt + ":" + KnownGcmNonce + ":" + KnownGcmSealed)]
    [InlineData("v2:-1:" + KnownGcmSalt + ":" + KnownGcmNonce + ":" + KnownGcmSealed)]
    [InlineData("v2:0:" + KnownGcmSalt + ":" + KnownGcmNonce + ":" + KnownGcmSealed)]
    [InlineData("v2:6000001:" + KnownGcmSalt + ":" + KnownGcmNonce + ":" + KnownGcmSealed)]
    [InlineData("v2:2147483647:" + KnownGcmSalt + ":" + KnownGcmNonce + ":" + KnownGcmSealed)]
    [InlineData("v2:10000:@@@@:" + KnownGcmNonce + ":" + KnownGcmSealed)]
    [InlineData("v2:10000:AAAAAAAAAAAAAAAA:" + KnownGcmNonce + ":" + KnownGcmSealed)]
    [InlineData("v2:10000:" + KnownGcmSalt + ":AAAAAAAAAAAAAAAAAAAAAA==:" + KnownGcmSealed)]
    [InlineData("v2:10000:" + KnownGcmSalt + ":" + KnownGcmNonce + ":AAAAAAAAAAA=")]
    public void AesGcmDecrypt_MalformedPayloadReturnsValidationError_Test(string payload)
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesGcmDecrypt(Password, payload);

        // Assert.
        result.IsError.ShouldBeTrue();
        result.FirstError.Type.ShouldBe(ErrorType.Validation);
        result.FirstError.Code.ShouldBe("AesGcm.InvalidPayload");
    }

    /// <summary>
    /// <see cref="AesCryptography.AesDecrypt"/> reads the authenticated format too, so a caller can
    /// switch to <see cref="AesCryptography.AesGcmEncrypt"/> and keep decrypting old and new data with
    /// one call.
    /// </summary>
    [Fact]
    public void AesDecrypt_ReadsGcmPayload_Test()
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, KnownGcmPayload);

        // Assert.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    /// <summary>
    /// <see cref="AesCryptography.AesDecrypt"/> keeps its contract for the authenticated format: a
    /// failure hands the input back, as a success.
    /// </summary>
    [Fact]
    public void AesDecrypt_GcmPayloadWithWrongPasswordReturnsInput_Test()
    {
        // Act.
        ErrorOr<string> result = AesCryptography.AesDecrypt("the-wrong-password", KnownGcmPayload);

        // Assert.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(KnownGcmPayload);
    }

    /// <summary>
    /// The formats are told apart by the prefix "v2:", colon included. The Base64 IV of an
    /// <c>AesEncrypt</c> payload starts with "v2" about once in 4,096 payloads; such a payload must
    /// still decrypt as the CBC format.
    /// </summary>
    [Fact]
    public void AesDecrypt_CbcPayloadWhoseIvStartsWithV2_Test()
    {
        // Arrange: a CBC payload built as AesEncrypt builds it, with an IV whose Base64 text starts
        // with "v2".
        const string ivText = "v2AAAAAAAAAAAAAAAAAAAA==";
        byte[] iv = Convert.FromBase64String(ivText);
        using Aes aes = Aes.Create();
        aes.Key = AesCryptography.MakeAESKey(Password, ivText).Value;
        string payload = $"{ivText}:{Convert.ToBase64String(aes.EncryptCbc(Encoding.UTF8.GetBytes(PlainText), iv))}";

        // Act.
        ErrorOr<string> result = AesCryptography.AesDecrypt(Password, payload);

        // Assert.
        result.IsError.ShouldBeFalse();
        result.Value.ShouldBe(PlainText);
    }

    /// <summary>
    /// Changes one part of a payload of the authenticated format: the iteration count by one, or one
    /// bit of the salt, the nonce, the first ciphertext byte or the last tag byte.
    /// </summary>
    /// <param name="payload">A valid payload.</param>
    /// <param name="part">The part to change.</param>
    /// <returns>The changed payload.</returns>
    private static string ChangeGcmPayload(string payload, string part)
    {
        string[] parts = payload.Split(':');

        switch (part)
        {
            case "iterations":
                int iterations = int.Parse(parts[1], CultureInfo.InvariantCulture);
                parts[1] = (iterations + 1).ToString(CultureInfo.InvariantCulture);
                break;
            case "salt":
                parts[2] = FlipBit(parts[2], 0);
                break;
            case "nonce":
                parts[3] = FlipBit(parts[3], 0);
                break;
            case "ciphertext":
                parts[4] = FlipBit(parts[4], 0);
                break;
            case "tag":
                parts[4] = FlipBit(parts[4], ^1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(part), part, "Unknown payload part.");
        }

        return string.Join(':', parts);
    }

    /// <summary>
    /// Flips the lowest bit of one byte of Base64 data.
    /// </summary>
    /// <param name="base64">The Base64 text.</param>
    /// <param name="byteIndex">The byte to change.</param>
    /// <returns>The changed data as Base64 text.</returns>
    private static string FlipBit(string base64, Index byteIndex)
    {
        byte[] bytes = Convert.FromBase64String(base64);
        bytes[byteIndex] ^= 0x01;
        return Convert.ToBase64String(bytes);
    }

    #endregion
}
