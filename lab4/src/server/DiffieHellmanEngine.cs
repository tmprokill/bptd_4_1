using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lab4.Server;

/// <summary>
/// Двигун криптографічного обміну ключами Діффі-Хеллмана (DHKE)
/// Підтримує:
/// 1. Класичний попарний обмін (2-Party DH).
/// 2. Груповий кільцевий обмін для N >= 3 учасників (Circular Group Diffie-Hellman, GDH).
/// 3. Деривацію сесійного ключа AES-256 (через SHA-256 / HKDF).
/// 4. Симетричне шифрування повідомлень за стандартом AES-GCM (Authenticated Encryption).
/// 5. Демонстраційну симуляцію атаки Man-in-the-Middle (MITM).
/// </summary>
public class DiffieHellmanEngine
{
    // Безпечне 256-бітне просте число MODP (Sophie Germain safe prime: p = 2q + 1)
    // Дозволяє швидку візуалізацію та верифікацію математичних викладок
    public static readonly BigInteger DefaultPrime256 = BigInteger.Parse(
        "115792089237316195423570985008687907853269984665640564039457584007913129639747");
    public static readonly BigInteger DefaultGenerator256 = 2;

    // Промислове 2048-бітне просте число (RFC 3526 MODP Group 14)
    public static readonly BigInteger Rfc3526Group14Prime = BigInteger.Parse(
        "0" +
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        System.Globalization.NumberStyles.HexNumber);
    public static readonly BigInteger Rfc3526Group14Generator = 2;

    public BigInteger P { get; }
    public BigInteger G { get; }

    public DiffieHellmanEngine(bool use2048Bit = false)
    {
        if (use2048Bit)
        {
            P = Rfc3526Group14Prime;
            G = Rfc3526Group14Generator;
        }
        else
        {
            P = DefaultPrime256;
            G = DefaultGenerator256;
        }
    }

    /// <summary>
    /// Генерує криптографічно стійкий випадковий закритий ключ x у діапазоні [2, p - 2]
    /// </summary>
    public BigInteger GeneratePrivateKey()
    {
        byte[] bytes = new byte[P.ToByteArray().Length];
        BigInteger x;
        do
        {
            RandomNumberGenerator.Fill(bytes);
            x = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            x = (x % (P - 4)) + 2;
        } while (x < 2 || x >= P - 1);

        return x;
    }

    /// <summary>
    /// Обчислює відкритий ключ: Y = g^x mod p
    /// </summary>
    public BigInteger ComputePublicKey(BigInteger privateKey)
    {
        return BigInteger.ModPow(G, privateKey, P);
    }

    /// <summary>
    /// Обчислює спільний секрет для 2-х сторін: K = (Y_peer)^privateKey mod p
    /// </summary>
    public BigInteger ComputeSharedSecret(BigInteger peerPublicKey, BigInteger privateKey)
    {
        return BigInteger.ModPow(peerPublicKey, privateKey, P);
    }

    /// <summary>
    /// Виконує повний протокол групового обміну ключами (Circular Group Diffie-Hellman)
    /// для довільної кількості учасників N >= 3.
    /// Кожен учасник i має власний закритий ключ x_i.
    /// Усі учасники в результаті обчислюють ідентичний груповий ключ:
    /// K = g^(x_1 * x_2 * ... * x_N) mod p
    /// </summary>
    public GroupDhResult ExecuteGroupKeyExchange(List<Participant> participants)
    {
        if (participants == null || participants.Count < 3)
            throw new ArgumentException("Для групового протоколу Діффі-Хеллмана потрібно щонайменше 3 учасники.");

        int n = participants.Count;
        var steps = new List<GroupRoundStep>();

        // Раунд 1: Кожен учасник i обчислює g^(x_i) mod p і передає сусіду праворуч
        var round1Values = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            round1Values[i] = BigInteger.ModPow(G, participants[i].PrivateKey, P);
            steps.Add(new GroupRoundStep(
                Round: 1,
                FromParticipant: participants[i].Name,
                ToParticipant: participants[(i + 1) % n].Name,
                Value: round1Values[i],
                Formula: $"g^(x_{participants[i].Name}) mod p"
            ));
        }

        // Поточні транзитні значення для кожного учасника
        // Учасник i тримає значення, отримане від сусіда (i-1)
        var currentToken = new BigInteger[n];
        for (int i = 0; i < n; i++)
        {
            int prev = (i - 1 + n) % n;
            currentToken[i] = round1Values[prev];
        }

        // Раунди 2 .. N-1: Проміжне каскадне піднесення до степеня
        for (int round = 2; round < n; round++)
        {
            var nextToken = new BigInteger[n];
            for (int i = 0; i < n; i++)
            {
                // Учасник i підносить отримане значення до власного степеня
                BigInteger compounded = BigInteger.ModPow(currentToken[i], participants[i].PrivateKey, P);
                int next = (i + 1) % n;
                nextToken[next] = compounded;

                steps.Add(new GroupRoundStep(
                    Round: round,
                    FromParticipant: participants[i].Name,
                    ToParticipant: participants[next].Name,
                    Value: compounded,
                    Formula: $"Token^(x_{participants[i].Name}) mod p"
                ));
            }
            currentToken = nextToken;
        }

        // Фінальний раунд N: Кожен учасник підносить отримане значення до свого секрету і отримує K
        var sharedKeys = new Dictionary<string, BigInteger>();
        for (int i = 0; i < n; i++)
        {
            BigInteger finalKey = BigInteger.ModPow(currentToken[i], participants[i].PrivateKey, P);
            sharedKeys[participants[i].Name] = finalKey;
        }

        // Перевіряємо математичний збіг усіх ключів
        BigInteger referenceKey = sharedKeys.Values.First();
        bool allMatch = sharedKeys.Values.All(k => k == referenceKey);

        byte[] aesKey = DeriveAesKey(referenceKey);

        return new GroupDhResult(
            Success: allMatch,
            GroupSharedSecret: referenceKey,
            GroupSharedSecretHex: referenceKey.ToString("X"),
            AesKeyBase64: Convert.ToBase64String(aesKey),
            Steps: steps,
            ParticipantKeys: sharedKeys
        );
    }

    /// <summary>
    /// Деривація 256-бітного симетричного ключа AES із великого числа K за допомогою SHA-256
    /// </summary>
    public static byte[] DeriveAesKey(BigInteger sharedSecret)
    {
        byte[] secretBytes = sharedSecret.ToByteArray(isUnsigned: true, isBigEndian: true);
        return SHA256.HashData(secretBytes);
    }

    /// <summary>
    /// Симетричне автентифіковане шифрування повідомлення за стандартом AES-GCM (256-біт)
    /// </summary>
    public static EncryptedPayload EncryptAesGcm(string plainText, byte[] aesKey)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] nonce = new byte[12]; // 96-бітний стандартний GCM nonce
        RandomNumberGenerator.Fill(nonce);

        byte[] ciphertext = new byte[plainBytes.Length];
        byte[] tag = new byte[16]; // 128-бітний автентифікаційний тег

        using var aesGcm = new AesGcm(aesKey, 16);
        aesGcm.Encrypt(nonce, plainBytes, ciphertext, tag);

        return new EncryptedPayload(
            CiphertextBase64: Convert.ToBase64String(ciphertext),
            NonceBase64: Convert.ToBase64String(nonce),
            TagBase64: Convert.ToBase64String(tag)
        );
    }

    /// <summary>
    /// Симетричне дешифрування та перевірка цілісності повідомлення за стандартом AES-GCM
    /// </summary>
    public static string DecryptAesGcm(EncryptedPayload payload, byte[] aesKey)
    {
        byte[] ciphertext = Convert.FromBase64String(payload.CiphertextBase64);
        byte[] nonce = Convert.FromBase64String(payload.NonceBase64);
        byte[] tag = Convert.FromBase64String(payload.TagBase64);

        byte[] decrypted = new byte[ciphertext.Length];
        using var aesGcm = new AesGcm(aesKey, 16);
        aesGcm.Decrypt(nonce, ciphertext, tag, decrypted);

        return Encoding.UTF8.GetString(decrypted);
    }

    /// <summary>
    /// Симуляція атаки Man-in-the-Middle (MITM) зловмисником "Євою":
    /// Перехоплює відкриті ключі між Алісою та Бобом, підміняючи їх на власні.
    /// В результаті утворюються два різних ключі (K_Alice-Eve та K_Eve-Bob),
    /// що дозволяє Єві читати та модифікувати трафік непомітно для обох сторін.
    /// </summary>
    public MitmSimulationResult SimulateMitmAttack(BigInteger alicePriv, BigInteger bobPriv)
    {
        BigInteger alicePub = ComputePublicKey(alicePriv);
        BigInteger bobPub = ComputePublicKey(bobPriv);

        // Зловмисник Єва генерує дві власні фіктивні пари ключів
        BigInteger evePrivAlice = GeneratePrivateKey();
        BigInteger evePubAlice = ComputePublicKey(evePrivAlice);

        BigInteger evePrivBob = GeneratePrivateKey();
        BigInteger evePubBob = ComputePublicKey(evePrivBob);

        // Аліса думає, що спілкується з Бобом, а отримує відкритий ключ Єви
        BigInteger keyAlice = ComputeSharedSecret(evePubAlice, alicePriv);
        BigInteger keyEveWithAlice = ComputeSharedSecret(alicePub, evePrivAlice);

        // Боб думає, що спілкується з Алісою, а отримує відкритий ключ Єви
        BigInteger keyBob = ComputeSharedSecret(evePubBob, bobPriv);
        BigInteger keyEveWithBob = ComputeSharedSecret(bobPub, evePrivBob);

        bool aliceEveMatch = (keyAlice == keyEveWithAlice);
        bool bobEveMatch = (keyBob == keyEveWithBob);
        bool victimKeysDirectMatch = (keyAlice == keyBob); // Має бути FALSE, бо ключі різні!

        return new MitmSimulationResult(
            AliceRealPublicKey: alicePub.ToString("X"),
            BobRealPublicKey: bobPub.ToString("X"),
            EveForgedPublicKeyForAlice: evePubAlice.ToString("X"),
            EveForgedPublicKeyForBob: evePubBob.ToString("X"),
            KeyAliceCalculated: keyAlice.ToString("X"),
            KeyBobCalculated: keyBob.ToString("X"),
            KeyEveAliceTunnel: keyEveWithAlice.ToString("X"),
            KeyEveBobTunnel: keyEveWithBob.ToString("X"),
            IsTrafficCompromised: aliceEveMatch && bobEveMatch,
            VictimsShareSameKey: victimKeysDirectMatch
        );
    }
}

public record Participant(string Name, BigInteger PrivateKey);

public record GroupRoundStep(
    int Round,
    string FromParticipant,
    string ToParticipant,
    BigInteger Value,
    string Formula
);

public record GroupDhResult(
    bool Success,
    BigInteger GroupSharedSecret,
    string GroupSharedSecretHex,
    string AesKeyBase64,
    List<GroupRoundStep> Steps,
    Dictionary<string, BigInteger> ParticipantKeys
);

public record EncryptedPayload(
    string CiphertextBase64,
    string NonceBase64,
    string TagBase64
);

public record MitmSimulationResult(
    string AliceRealPublicKey,
    string BobRealPublicKey,
    string EveForgedPublicKeyForAlice,
    string EveForgedPublicKeyForBob,
    string KeyAliceCalculated,
    string KeyBobCalculated,
    string KeyEveAliceTunnel,
    string KeyEveBobTunnel,
    bool IsTrafficCompromised,
    bool VictimsShareSameKey
);
