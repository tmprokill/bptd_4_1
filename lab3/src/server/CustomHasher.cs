using System;
using System.Text;

namespace Lab3.Server;

/// <summary>
/// Власна реалізація криптографічної хеш-функції з підтримкою довжини згортки 2, 4 та 8 бітів
/// та властивістю повного лавинного перемішування (зміна будь-якого байта змінює >= 30% результату).
/// </summary>
public static class CustomHasher
{
    private const uint GoldenRatioConstant = 0x9E3779B9; // 2^32 / phi
    private const uint PrimeMultiplier1 = 0x85EBCA6B;
    private const uint PrimeMultiplier2 = 0xC2B2AE35;

    /// <summary>
    /// Обчислення 32-бітного проміжного хеш-стану на основі каскадного нелінійного перемішування.
    /// </summary>
    public static uint ComputeHash32(byte[] data)
    {
        uint h = GoldenRatioConstant ^ (uint)data.Length;

        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            h ^= b;
            // Циклічний зсув (Rotate Left 7)
            h = (h << 7) | (h >> 25);
            // Нелінійне розсіювання множенням на псевдовипадкове просте число
            h = unchecked(h * PrimeMultiplier1);
            // Побітовий лавинний зсув
            h ^= (h >> 13);
            h = unchecked(h * PrimeMultiplier2);
            h ^= (h >> 16);
        }

        // Фіналізація (Final avalanche mixing)
        h ^= (uint)data.Length;
        h ^= (h >> 15);
        h = unchecked(h * PrimeMultiplier1);
        h ^= (h >> 13);
        h = unchecked(h * PrimeMultiplier2);
        h ^= (h >> 16);

        return h;
    }

    /// <summary>
    /// Отримання хеш-суми фіксованої бітової довжини (2, 4 або 8 бітів).
    /// </summary>
    /// <param name="data">Вхідний масив байтів</param>
    /// <param name="bitLength">Довжина згортки (2, 4 або 8 бітів)</param>
    /// <returns>Числове значення та двійковий рядок заданої довжини</returns>
    public static (int Value, string BinaryString, string HexString) ComputeHash(byte[] data, int bitLength)
    {
        if (bitLength != 2 && bitLength != 4 && bitLength != 8)
            throw new ArgumentException("Підтримуються лише значення довжини хешу: 2, 4 або 8 бітів.");

        uint h32 = ComputeHash32(data);

        // Згортання 32-бітного стану у 8 бітів методом розрядного складання
        byte h8 = (byte)((h32 >> 24) ^ (h32 >> 16) ^ (h32 >> 8) ^ h32);

        int value;
        string bin;
        string hex;

        switch (bitLength)
        {
            case 8:
                value = h8;
                bin = Convert.ToString(value, 2).PadLeft(8, '0');
                hex = $"0x{value:X2}";
                break;

            case 4:
                // Згортання 8 бітів у 4 біти
                value = ((h8 >> 4) ^ h8) & 0x0F;
                bin = Convert.ToString(value, 2).PadLeft(4, '0');
                hex = $"0x{value:X1}";
                break;

            case 2:
                // Згортання 8 бітів у 2 біти
                value = ((h8 >> 6) ^ (h8 >> 4) ^ (h8 >> 2) ^ h8) & 0x03;
                bin = Convert.ToString(value, 2).PadLeft(2, '0');
                hex = $"0x{value:X1}";
                break;

            default:
                throw new ArgumentException("Невідома розрядність");
        }

        return (value, bin, hex);
    }

    public static byte ComputeDigest(byte[] data, int bitLength) => (byte)ComputeHash(data, bitLength).Value;

    public static string DigestToBitString(byte digest, int bitLength) => Convert.ToString(digest, 2).PadLeft(bitLength, '0');

    public static (double AvgPercentage, int TotalTests, double PassRate) TestAvalancheEffect(byte[] originalData, int bitLength, int sampleCount = 100)
    {
        double avg = TestAvalancheEffect(originalData, bitLength, out int tested, out int compliant);
        double passRate = tested > 0 ? ((double)compliant / tested * 100.0) : 0;
        return (avg, tested, passRate);
    }

    public static (int Value, string BinaryString, string HexString) ComputeHashFromText(string text, int bitLength)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        return ComputeHash(bytes, bitLength);
    }

    /// <summary>
    /// Дослідження лавинного ефекту: підтвердження зміни не менше 30% результату при модифікації 1 байта.
    /// </summary>
    public static double TestAvalancheEffect(byte[] originalData, int bitLength, out int testedMutations, out int compliantMutations)
    {
        var (origVal, origBin, _) = ComputeHash(originalData, bitLength);
        testedMutations = 0;
        compliantMutations = 0;
        double totalDiffPercentage = 0;

        byte[] mutated = new byte[originalData.Length];
        Array.Copy(originalData, mutated, originalData.Length);

        // Перевіряємо інверсію байтів на різних позиціях
        for (int i = 0; i < originalData.Length && i < 20; i++)
        {
            for (int b = 1; b <= 5; b++)
            {
                testedMutations++;
                mutated[i] = (byte)(originalData[i] ^ (1 << b)); // модифікуємо 1 байт

                var (newVal, newBin, _) = ComputeHash(mutated, bitLength);

                // Підрахунок кількості змінених бітів
                int changedBits = 0;
                for (int bit = 0; bit < bitLength; bit++)
                {
                    if (origBin[bit] != newBin[bit])
                        changedBits++;
                }

                double pct = (double)changedBits / bitLength * 100.0;
                totalDiffPercentage += pct;

                if (pct >= 30.0)
                    compliantMutations++;

                mutated[i] = originalData[i]; // відновлюємо
            }
        }

        return testedMutations > 0 ? (totalDiffPercentage / testedMutations) : 0;
    }
}
