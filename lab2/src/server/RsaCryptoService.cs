using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RsaServer;

/// <summary>
/// Сервіс асиметричної криптографії RSA на базі стандартної системної бібліотеки .NET (System.Security.Cryptography).
/// Забезпечує генерацію ключів 2048 біт, експорт/імпорт у стандарті SPKI PEM та блокове шифрування/розшифрування
/// за схемою RSA-OAEP-SHA256 (розмір блоку відкритого тексту до 190 байтів, шифротексту - 256 байтів).
/// </summary>
public class RsaCryptoService : IDisposable
{
    private readonly RSA _serverRsa;
    public string ServerPublicKeyPem { get; }
    public int KeySize => _serverRsa.KeySize;

    public const int MaxPlainChunkSize = 190;  // 256 - 2*32 - 2 = 190 байтів для OAEP-SHA256
    public const int CipherChunkSize = 256;    // 2048 бітів = 256 байтів

    public RsaCryptoService(int keySize = 2048)
    {
        _serverRsa = RSA.Create(keySize);
        ServerPublicKeyPem = _serverRsa.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>
    /// Блокове розшифрування повідомлення клієнта приватним ключем сервера.
    /// Розбиває вхідний потік на 256-байтні RSA-криптограми та розшифровує кожну з них.
    /// </summary>
    public string DecryptFromClient(string encryptedBase64)
    {
        byte[] cipherBytes = Convert.FromBase64String(encryptedBase64);
        using var ms = new MemoryStream();

        for (int offset = 0; offset < cipherBytes.Length; offset += CipherChunkSize)
        {
            int count = Math.Min(CipherChunkSize, cipherBytes.Length - offset);
            byte[] chunk = new byte[count];
            Buffer.BlockCopy(cipherBytes, offset, chunk, 0, count);

            byte[] decChunk = _serverRsa.Decrypt(chunk, RSAEncryptionPadding.OaepSHA256);
            ms.Write(decChunk, 0, decChunk.Length);
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>
    /// Блокове шифрування повідомлення для клієнта його публічним ключем.
    /// Розбиває довгі повідомлення на блоки по 190 байтів та формує конкатенований шифротекст.
    /// </summary>
    public string EncryptForClient(string plainText, string clientPublicKeyPem)
    {
        using var clientRsa = RSA.Create();
        clientRsa.ImportFromPem(clientPublicKeyPem);

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        using var ms = new MemoryStream();

        for (int offset = 0; offset < plainBytes.Length; offset += MaxPlainChunkSize)
        {
            int count = Math.Min(MaxPlainChunkSize, plainBytes.Length - offset);
            byte[] chunk = new byte[count];
            Buffer.BlockCopy(plainBytes, offset, chunk, 0, count);

            byte[] encChunk = clientRsa.Encrypt(chunk, RSAEncryptionPadding.OaepSHA256);
            ms.Write(encChunk, 0, encChunk.Length);
        }

        return Convert.ToBase64String(ms.ToArray());
    }

    public void Dispose()
    {
        _serverRsa.Dispose();
        GC.SuppressFinalize(this);
    }
}
