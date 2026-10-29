using System;
using System.Security.Cryptography;
using System.Text;

namespace Lab3.Server;

public class RsaSigner : IDisposable
{
    private readonly RSA _rsa;

    public string PublicKeyPem { get; }
    public string PrivateKeyPem { get; }

    public RsaSigner(int keySize = 2048)
    {
        _rsa = RSA.Create(keySize);
        PublicKeyPem = _rsa.ExportSubjectPublicKeyInfoPem();
        PrivateKeyPem = _rsa.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>
    /// Signs the given hash digest using RSA-PKCS#1 v1.5 with SHA-256
    /// </summary>
    public string SignDigest(byte[] digest)
    {
        byte[] signature = _rsa.SignData(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }

    /// <summary>
    /// Verifies the RSA signature for the given hash digest using the internal key
    /// </summary>
    public bool VerifyDigest(byte[] digest, string signatureBase64)
    {
        try
        {
            byte[] signature = Convert.FromBase64String(signatureBase64);
            return _rsa.VerifyData(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Static helper to verify a signature with any public key PEM
    /// </summary>
    public static bool VerifyWithPublicKey(byte[] digest, string signatureBase64, string publicKeyPem)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            byte[] signature = Convert.FromBase64String(signatureBase64);
            return rsa.VerifyData(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        _rsa.Dispose();
    }
}
