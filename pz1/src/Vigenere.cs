using System;
using System.Text;

public class Vigenere
{
    public const string AlphabetUpper = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";
    public const string AlphabetLower = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя";

    /// <summary>
    /// Шифрування тексту шифром Віженера за ключовим словом key.
    /// Працює над українським алфавітом (33 літери).
    /// Регістр літер зберігається, пробіли та розділові знаки не змінюються
    /// та не зсувають позицію ключового слова.
    /// </summary>
    public static string Encrypt(string plainText, string key)
    {
        if (plainText == null) throw new ArgumentNullException(nameof(plainText));
        if (string.IsNullOrEmpty(key)) throw new ArgumentException("Ключ не може бути порожнім", nameof(key));

        int n = AlphabetUpper.Length; // 33 літери
        var sb = new StringBuilder(plainText.Length);
        int keyIndex = 0;

        foreach (char c in plainText)
        {
            int upperIndex = AlphabetUpper.IndexOf(c);
            int lowerIndex = AlphabetLower.IndexOf(c);

            if (upperIndex >= 0 || lowerIndex >= 0)
            {
                // Отримуємо зсув з поточної літери ключа
                int keyShift = GetKeyShift(key, keyIndex);
                keyIndex++;

                if (upperIndex >= 0)
                {
                    int newIndex = (upperIndex + keyShift) % n;
                    sb.Append(AlphabetUpper[newIndex]);
                }
                else
                {
                    int newIndex = (lowerIndex + keyShift) % n;
                    sb.Append(AlphabetLower[newIndex]);
                }
            }
            else
            {
                // Розділові знаки, цифри, пробіли, апострофи не змінюють індекс ключа
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Дешифрування тексту шифром Віженера за ключовим словом key.
    /// </summary>
    public static string Decrypt(string cipherText, string key)
    {
        if (cipherText == null) throw new ArgumentNullException(nameof(cipherText));
        if (string.IsNullOrEmpty(key)) throw new ArgumentException("Ключ не може бути порожнім", nameof(key));

        int n = AlphabetUpper.Length; // 33 літери
        var sb = new StringBuilder(cipherText.Length);
        int keyIndex = 0;

        foreach (char c in cipherText)
        {
            int upperIndex = AlphabetUpper.IndexOf(c);
            int lowerIndex = AlphabetLower.IndexOf(c);

            if (upperIndex >= 0 || lowerIndex >= 0)
            {
                int keyShift = GetKeyShift(key, keyIndex);
                keyIndex++;

                if (upperIndex >= 0)
                {
                    int newIndex = (upperIndex - keyShift + n) % n;
                    sb.Append(AlphabetUpper[newIndex]);
                }
                else
                {
                    int newIndex = (lowerIndex - keyShift + n) % n;
                    sb.Append(AlphabetLower[newIndex]);
                }
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    private static int GetKeyShift(string key, int index)
    {
        int n = AlphabetUpper.Length;
        for (int i = 0; i < key.Length; i++)
        {
            char kc = key[(index + i) % key.Length];
            int up = AlphabetUpper.IndexOf(kc);
            if (up >= 0) return up;
            int low = AlphabetLower.IndexOf(kc);
            if (low >= 0) return low;
        }
        return 0;
    }

    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length >= 3)
        {
            string command = args[0].ToLowerInvariant();
            string text = args[1];
            string key = args[2];

            if (command == "encrypt" || command == "enc" || command == "e")
            {
                Console.WriteLine($"Зашифрований текст: {Encrypt(text, key)}");
                return;
            }
            if (command == "decrypt" || command == "dec" || command == "d")
            {
                Console.WriteLine($"Розшифрований текст: {Decrypt(text, key)}");
                return;
            }
        }

        Console.WriteLine("==================================================");
        Console.WriteLine("         ПРОГРАМА: ШИФР ВІЖЕНЕРА (.NET)");
        Console.WriteLine("==================================================");

        // Демонстрація 1: Завдання 2 (Таблиця 1.2, Рядок 1, ключ "ключ")
        Console.WriteLine("\n--- ЗАВДАННЯ 2 (Таблиця 1.2, Рядок 1, Ключ: \"ключ\") ---");
        string originalZ2 = "Асиметрична криптографія стала елегантним розв'язанням задачі розподілу ключів. " +
                            "Але як це часто буває, те, що допомогло усунути одну проблему, стало причиною " +
                            "виникнення іншої. Відкритий ключ, в силу математичних властивостей асиметричних " +
                            "криптоалгоритмів є набором випадкових біт.";
        string keyZ2 = "ключ";
        string cipherZ2 = Vigenere.Encrypt(originalZ2, keyZ2);
        string decryptedZ2 = Vigenere.Decrypt(cipherZ2, keyZ2);

        Console.WriteLine($"Оригінальний текст:\n{originalZ2}");
        Console.WriteLine($"Зашифровано:\n{cipherZ2}");
        Console.WriteLine($"Розшифровано:\n{decryptedZ2}");
        Console.WriteLine($"Збіг: {originalZ2 == decryptedZ2}");

        // Демонстрація 2: Завдання 3 для Варіанту 16 (Чуваєв А. О., Рядок 2, Ключ: "Лишити")
        Console.WriteLine("\n--- ЗАВДАННЯ 3: ВАРІАНТ 16: Чуваєв А. О. (Таблиця 1.3, Рядок 2, Ключ: \"Лишити\") ---");
        string cipherZ3_16 = "Бмлдяц бьй южьаебчез жсвт ивсцд птлдцшїиз Лле Дтцць 1984 лшга. " +
                             "Нсї щзрбамяяї, іш чфур ф'зьрґигз ішьххїеюіє нрзшзргяйїїїляд зг їцлзьяяху " +
                             "зхрґ цц'ч иуш бшуяєїд иаьшюд Иисир, ґш см жшфішїяха і мфґирчо щзшжмааза " +
                             "лїнмеяхбефтгцт щачє-кфййє юсчма. Чшнйду миг самс Длцеьт плхддтхлюч хядс " +
                             "флиирншц фзрбяййзиестчєж ошишфшьшіфєж, лхб ї 2000 зшжс, ґифлкфд шччцу " +
                             "ьсчшюсж їзифхдїєюґс ь мґсбядґесш флржяайлийсч, самр їриишиз няехяях ї гріяк.";
        string keyZ3_16 = "Лишити";
        string decryptedZ3_16 = Vigenere.Decrypt(cipherZ3_16, keyZ3_16);
        string reEncryptedZ3_16 = Vigenere.Encrypt(decryptedZ3_16, keyZ3_16);

        Console.WriteLine($"Шифротекст:\n{cipherZ3_16}");
        Console.WriteLine($"Розшифровано за ключем \"{keyZ3_16}\":\n{decryptedZ3_16}");
        Console.WriteLine($"Повторне шифрування збігається: {cipherZ3_16 == reEncryptedZ3_16}");

        // Демонстрація 3: Завдання 3 для Варіанту 13 (Світенко С. М., Рядок 6, Ключ: "набір")
        Console.WriteLine("\n--- ЗАВДАННЯ 3: ВАРІАНТ 13: Світенко С. М. (Таблиця 1.3, Рядок 6, Ключ: \"набір\") ---");
        string cipherZ3_13 = "Нсічцерідґн кссееоґюржіа язнлб нвугбшзбин юдцв'аррбнач щндбдю ґоиьдтімб бяюштт. " +
                             "Нлє иб ие шіжео вбтнє, ун, мв дпьдаоґцд єсфшиеи пмґє псщсяенб, жеамщ еґишсґвю " +
                             "гсґчконґбя їшлвї. Гтхюріаьь кмзк, п сіци ааунгнтідґчх гцрдтійддтєф рдиннзґишшьз " +
                             "кссееобцувріагшв ж шроосщг пиріхюогсї оіу.";
        string keyZ3_13 = "набір";
        string decryptedZ3_13 = Vigenere.Decrypt(cipherZ3_13, keyZ3_13);
        string reEncryptedZ3_13 = Vigenere.Encrypt(decryptedZ3_13, keyZ3_13);

        Console.WriteLine($"Шифротекст:\n{cipherZ3_13}");
        Console.WriteLine($"Розшифровано за ключем \"{keyZ3_13}\":\n{decryptedZ3_13}");
        Console.WriteLine($"Повторне шифрування збігається: {cipherZ3_13 == reEncryptedZ3_13}");
    }
}
