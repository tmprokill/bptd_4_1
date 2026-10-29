using System;
using System.Collections.Generic;
using System.Text;

namespace DesCipher;

/// <summary>
/// Реалізація криптографічного рушія алгоритму шифрування DES (Data Encryption Standard)
/// відповідно до стандарту FIPS PUB 46 без використання зовнішніх бібліотек.
/// </summary>
public static class DesEngine
{
    #region Побітові перестановки та математичні утиліти

    /// <summary>
    /// Отримання значення біта за 1-базованим індексом біта (від 1 до totalBits).
    /// Біт 1 - це найстарший біт (MSB).
    /// </summary>
    public static ulong GetBit(ulong val, int bitIndex1Based, int totalBits)
    {
        int shift = totalBits - bitIndex1Based;
        return (val >> shift) & 1UL;
    }

    /// <summary>
    /// Перестановка бітів у 64-бітному або меншому слові за заданою таблицею.
    /// </summary>
    public static ulong Permute(ulong input, byte[] table, int inputBits)
    {
        ulong result = 0;
        for (int i = 0; i < table.Length; i++)
        {
            int bitPos = table[i];
            ulong bit = GetBit(input, bitPos, inputBits);
            result = (result << 1) | bit;
        }
        return result;
    }

    /// <summary>
    /// 28-бітний циклічний зсув уліво (Circular Left Shift).
    /// </summary>
    public static uint RotateLeft28(uint val, int shift)
    {
        val &= 0x0FFFFFFF; // маска 28 бітів
        return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
    }

    /// <summary>
    /// Конвертація 8 байтів у 64-бітне беззнакове ціле (Big-Endian).
    /// </summary>
    public static ulong BytesToUlongBigEndian(byte[] data, int offset)
    {
        ulong res = 0;
        for (int i = 0; i < 8; i++)
        {
            res = (res << 8) | data[offset + i];
        }
        return res;
    }

    /// <summary>
    /// Конвертація 64-бітного беззнакового цілого у 8 байтів (Big-Endian).
    /// </summary>
    public static void UlongToBytesBigEndian(ulong val, byte[] output, int offset)
    {
        for (int i = 7; i >= 0; i--)
        {
            output[offset + i] = (byte)(val & 0xFF);
            val >>= 8;
        }
    }

    public static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("-", "");
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Hex рядок має містити парну кількість символів");

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    public static string BytesToHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            sb.Append(b.ToString("X2"));
        }
        return sb.ToString();
    }

    #endregion

    #region Генерація раундових ключів (Key Schedule)

    /// <summary>
    /// Генерація 16 раундових 48-бітних підключів із 64-бітного початкового ключа.
    /// </summary>
    public static ulong[] GenerateSubkeys(ulong rawKey64)
    {
        ulong[] subkeys = new ulong[16];

        // 1. Початкова перестановка зі стисненням PC-1 (64 біти -> 56 бітів)
        ulong key56 = Permute(rawKey64, DesTables.PC1, 64);

        // 2. Розбиття на дві 28-бітні половини: C0 (старші 28) та D0 (молодші 28)
        uint C = (uint)((key56 >> 28) & 0x0FFFFFFF);
        uint D = (uint)(key56 & 0x0FFFFFFF);

        for (int round = 0; round < 16; round++)
        {
            // Циклічний зсув регістрів C та D на 1 або 2 біти
            int shift = DesTables.SHIFTS[round];
            C = RotateLeft28(C, shift);
            D = RotateLeft28(D, shift);

            // Об'єднання Ci та Di у 56-бітне число
            ulong CD = ((ulong)C << 28) | D;

            // Стиснення PC-2 (56 бітів -> 48 бітів)
            subkeys[round] = Permute(CD, DesTables.PC2, 56);
        }

        return subkeys;
    }

    #endregion

    #region Раундова функція Фейстеля f(R, K)

    /// <summary>
    /// Автентична функція Фейстеля f(R, K) відповідно до стандарту FIPS PUB 46:
    /// 1. Розширення E (32 -> 48 біт)
    /// 2. XOR з 48-бітним підключем
    /// 3. Заміна в 8 нелінійних S-блоках (48 -> 32 біт)
    /// 4. Пряма перестановка P (32 -> 32 біт)
    /// </summary>
    public static uint FeistelF(uint R, ulong roundKey48)
    {
        // 1. Розширення правої 32-бітної половини до 48 бітів
        ulong expandedR = Permute(R, DesTables.E, 32);

        // 2. Додавання за модулем 2 з раундовим підключем
        ulong xorBlock = (expandedR ^ roundKey48) & 0x0000FFFFFFFFFFFFUL;

        // 3. Проходження крізь 8 S-блоків заміни
        uint sboxOutput = 0;
        for (int i = 0; i < 8; i++)
        {
            // Виділення 6-бітового блоку Bi (починаючи з B1 до B8)
            int shift = 42 - (i * 6);
            int sixBits = (int)((xorBlock >> shift) & 0x3F);

            // Перший і шостий біти визначають рядок (0..3)
            int row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);

            // Середні 4 біти (2, 3, 4, 5) визначають стовпець (0..15)
            int col = (sixBits >> 1) & 0x0F;

            int index = row * 16 + col;
            byte sVal = DesTables.SBOXES[i][index]; // 4-бітове значення

            sboxOutput = (sboxOutput << 4) | (uint)(sVal & 0x0F);
        }

        // 4. Пряма перестановка P (32 біти -> 32 біти)
        uint permutedOutput = (uint)Permute(sboxOutput, DesTables.P, 32);
        return permutedOutput;
    }

    #endregion

    #region Шифрування та дешифрування окремого 64-бітного блоку

    /// <summary>
    /// Шифрування одного 64-бітного блоку з можливістю фіксації проміжних станів для ентропії.
    /// </summary>
    public static ulong EncryptBlock(ulong block64, ulong[] subkeys, List<RoundState>? roundStates = null)
    {
        if (roundStates != null)
        {
            var (ones, p1, ent) = CalculateEntropy(block64);
            roundStates.Add(new RoundState
            {
                StageName = "Вхід",
                L = (uint)(block64 >> 32),
                R = (uint)(block64 & 0xFFFFFFFF),
                FullBlock = block64,
                OnesCount = ones,
                P1 = p1,
                Entropy = ent
            });
        }

        // 1. Початкова перестановка IP
        ulong ipBlock = Permute(block64, DesTables.IP, 64);
        uint L = (uint)(ipBlock >> 32);
        uint R = (uint)(ipBlock & 0xFFFFFFFF);

        if (roundStates != null)
        {
            var (ones, p1, ent) = CalculateEntropy(ipBlock);
            roundStates.Add(new RoundState
            {
                StageName = "IP",
                L = L,
                R = R,
                FullBlock = ipBlock,
                OnesCount = ones,
                P1 = p1,
                Entropy = ent
            });
        }

        // 2. 16 раундів мережі Фейстеля
        for (int i = 0; i < 16; i++)
        {
            uint newR = L ^ FeistelF(R, subkeys[i]);
            L = R;
            R = newR;

            if (roundStates != null)
            {
                ulong currentFull = ((ulong)L << 32) | R;
                var (ones, p1, ent) = CalculateEntropy(currentFull);
                roundStates.Add(new RoundState
                {
                    StageName = $"Р{i + 1:D2}",
                    L = L,
                    R = R,
                    FullBlock = currentFull,
                    OnesCount = ones,
                    P1 = p1,
                    Entropy = ent
                });
            }
        }

        // 3. Кінцевий обмін половинами (R16 || L16)
        ulong preOutput = ((ulong)R << 32) | L;

        // 4. Фінальна зворотна перестановка IP^-1
        ulong cipherBlock = Permute(preOutput, DesTables.IP_INV, 64);

        if (roundStates != null)
        {
            var (ones, p1, ent) = CalculateEntropy(cipherBlock);
            roundStates.Add(new RoundState
            {
                StageName = "IP^-1",
                L = (uint)(cipherBlock >> 32),
                R = (uint)(cipherBlock & 0xFFFFFFFF),
                FullBlock = cipherBlock,
                OnesCount = ones,
                P1 = p1,
                Entropy = ent
            });
        }

        return cipherBlock;
    }

    /// <summary>
    /// Дешифрування одного 64-бітного блоку з використанням інверсного порядку підключів.
    /// </summary>
    public static ulong DecryptBlock(ulong cipherBlock64, ulong[] subkeys)
    {
        // 1. Початкова перестановка IP
        ulong ipBlock = Permute(cipherBlock64, DesTables.IP, 64);
        uint L = (uint)(ipBlock >> 32);
        uint R = (uint)(ipBlock & 0xFFFFFFFF);

        // 2. 16 раундів мережі Фейстеля (ключі подаються у зворотному порядку K16..K1)
        for (int i = 15; i >= 0; i--)
        {
            uint newR = L ^ FeistelF(R, subkeys[i]);
            L = R;
            R = newR;
        }

        // 3. Кінцевий обмін половинами (R16 || L16)
        ulong preOutput = ((ulong)R << 32) | L;

        // 4. Фінальна зворотна перестановка IP^-1
        return Permute(preOutput, DesTables.IP_INV, 64);
    }

    #endregion

    #region Набивання PKCS#7 та потокова обробка байтів

    public static byte[] ApplyPkcs7Padding(byte[] input)
    {
        int padLen = 8 - (input.Length % 8);
        if (padLen == 0) padLen = 8;

        byte[] padded = new byte[input.Length + padLen];
        Buffer.BlockCopy(input, 0, padded, 0, input.Length);
        for (int i = input.Length; i < padded.Length; i++)
        {
            padded[i] = (byte)padLen;
        }
        return padded;
    }

    public static byte[] RemovePkcs7Padding(byte[] input)
    {
        if (input.Length == 0 || input.Length % 8 != 0)
            throw new ArgumentException("Розмір вхідного масиву для зняття PKCS#7 має бути кратним 8");

        byte padLen = input[^1];
        if (padLen < 1 || padLen > 8)
            throw new ArgumentException("Некоректне значення байта набивання PKCS#7");

        for (int i = input.Length - padLen; i < input.Length; i++)
        {
            if (input[i] != padLen)
                throw new ArgumentException("Порушено цілісність байтів набивання PKCS#7");
        }

        byte[] unpadded = new byte[input.Length - padLen];
        Buffer.BlockCopy(input, 0, unpadded, 0, unpadded.Length);
        return unpadded;
    }

    public static byte[] EncryptBytes(byte[] data, byte[] key8, out List<List<RoundState>> allBlockStates)
    {
        if (key8.Length != 8)
            throw new ArgumentException("Довжина ключа DES повинна становити рівно 8 байтів (64 біти)");

        ulong rawKey = BytesToUlongBigEndian(key8, 0);
        ulong[] subkeys = GenerateSubkeys(rawKey);

        byte[] paddedData = ApplyPkcs7Padding(data);
        byte[] cipher = new byte[paddedData.Length];
        allBlockStates = new List<List<RoundState>>();

        for (int offset = 0; offset < paddedData.Length; offset += 8)
        {
            ulong block = BytesToUlongBigEndian(paddedData, offset);
            var states = new List<RoundState>();
            ulong cBlock = EncryptBlock(block, subkeys, states);
            allBlockStates.Add(states);
            UlongToBytesBigEndian(cBlock, cipher, offset);
        }

        return cipher;
    }

    public static byte[] DecryptBytes(byte[] cipherData, byte[] key8)
    {
        if (key8.Length != 8)
            throw new ArgumentException("Довжина ключа DES повинна становити рівно 8 байтів (64 біти)");
        if (cipherData.Length % 8 != 0)
            throw new ArgumentException("Розмір шифротексту повинен бути кратним 8 байтам");

        ulong rawKey = BytesToUlongBigEndian(key8, 0);
        ulong[] subkeys = GenerateSubkeys(rawKey);

        byte[] plain = new byte[cipherData.Length];
        for (int offset = 0; offset < cipherData.Length; offset += 8)
        {
            ulong cBlock = BytesToUlongBigEndian(cipherData, offset);
            ulong pBlock = DecryptBlock(cBlock, subkeys);
            UlongToBytesBigEndian(pBlock, plain, offset);
        }

        return RemovePkcs7Padding(plain);
    }

    public static string EncryptText(string text, byte[] key8, out List<List<RoundState>> allBlockStates)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(text);
        byte[] cipherBytes = EncryptBytes(plainBytes, key8, out allBlockStates);
        return BytesToHex(cipherBytes);
    }

    public static string DecryptText(string hexCipher, byte[] key8)
    {
        byte[] cipherBytes = HexToBytes(hexCipher);
        byte[] plainBytes = DecryptBytes(cipherBytes, key8);
        return Encoding.UTF8.GetString(plainBytes);
    }

    #endregion

    #region Розрахунок інформаційної ентропії Шеннона

    public static int CountOnes(ulong val)
    {
        int count = 0;
        while (val != 0)
        {
            val &= (val - 1);
            count++;
        }
        return count;
    }

    public static (int ones, double p1, double entropy) CalculateEntropy(ulong block64)
    {
        int ones = CountOnes(block64);
        double p1 = (double)ones / 64.0;
        double p0 = 1.0 - p1;

        double entropy = 0;
        if (p1 > 0)
            entropy -= p1 * Math.Log2(p1);
        if (p0 > 0)
            entropy -= p0 * Math.Log2(p0);

        return (ones, p1, entropy);
    }

    #endregion

    #region Перевірка на слабкі та напівслабкі ключі

    public static (bool IsWeak, string Description) CheckWeakKey(ulong key64)
    {
        // 1. Перевірка на Weak Keys
        foreach (var wk in DesTables.WeakKeys)
        {
            if (key64 == wk)
                return (true, "Слабкий ключ (Weak Key). Генерує 16 однакових підключів! Шифрування збігається з дешифруванням: E_k(E_k(M)) = M");
        }

        // 2. Перевірка на Semi-Weak Keys
        foreach (var (k1, k2) in DesTables.SemiWeakKeyPairs)
        {
            if (key64 == k1 || key64 == k2)
                return (true, "Напівслабкий ключ (Semi-Weak Key). Утворює пару ключів-близнюків (k1, k2), де E_k1(E_k2(M)) = M");
        }

        return (false, "Ключ коректний (не належить до множини слабких чи напівслабких)");
    }

    #endregion
}
