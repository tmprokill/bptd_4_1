using System;
using System.Text;

public class Caesar
{
    public const string AlphabetUpper = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";
    public const string AlphabetLower = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя";

    /// <summary>
    /// Шифрування тексту шифром Цезаря з ключем зсуву key.
    /// Нелітерні символи (розділові знаки, цифри, апостроф, пробіли) залишаються без змін.
    /// </summary>
    public static string Encrypt(string plainText, int key)
    {
        if (plainText == null) throw new ArgumentNullException(nameof(plainText));

        int n = AlphabetUpper.Length; // 33 літери українського алфавіту
        int normalizedShift = ((key % n) + n) % n;

        var sb = new StringBuilder(plainText.Length);
        foreach (char c in plainText)
        {
            int upperIndex = AlphabetUpper.IndexOf(c);
            if (upperIndex >= 0)
            {
                int newIndex = (upperIndex + normalizedShift) % n;
                sb.Append(AlphabetUpper[newIndex]);
                continue;
            }

            int lowerIndex = AlphabetLower.IndexOf(c);
            if (lowerIndex >= 0)
            {
                int newIndex = (lowerIndex + normalizedShift) % n;
                sb.Append(AlphabetLower[newIndex]);
                continue;
            }

            // Інші символи (розділові знаки, пробіли, апострофи) залишаються без змін
            sb.Append(c);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Дешифрування тексту шифром Цезаря з ключем зсуву key.
    /// </summary>
    public static string Decrypt(string cipherText, int key)
    {
        return Encrypt(cipherText, -key);
    }

    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length >= 3)
        {
            string command = args[0].ToLowerInvariant();
            string text = args[1];
            if (!int.TryParse(args[2], out int key))
            {
                Console.WriteLine("Помилка: ключ зсуву має бути цілим числом.");
                return;
            }

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
        Console.WriteLine("          ПРОГРАМА: ШИФР ЦЕЗАРЯ (.NET)");
        Console.WriteLine("==================================================");

        // Демонстрація для Варіанту 16 (Чуваєв А. О.)
        Console.WriteLine("\n--- ВАРІАНТ 16: Чуваєв А. О. (Ключ = 15) ---");
        string original16 = "В одну мить його перенесло через поріг! Вода обризкала гребців й присипала Карпові кучері. " +
                            "Судно тихо загуло, як порожня бочка. Всі перехрестились.";
        string cipher16 = Caesar.Encrypt(original16, 15);
        string decrypted16 = Caesar.Decrypt(cipher16, 15);

        Console.WriteLine($"Оригінальний текст:\n{original16}");
        Console.WriteLine($"Зашифровано (k=15):\n{cipher16}");
        Console.WriteLine($"Розшифровано:\n{decrypted16}");
        Console.WriteLine($"Збіг: {original16 == decrypted16}");

        // Демонстрація для Варіанту 13 (Світенко С. М.)
        Console.WriteLine("\n--- ВАРІАНТ 13: Світенко С. М. (Ключ = 21) ---");
        string original13 = "Гребці запустили гребки в воду. Байдак знявся з місця і полетів, як птиця. " +
                            "Коло стерна стояв, як той явір високий, Карпо Летючий. Серед Дніпра на судні " +
                            "в прозорому повітрі малювалося його молоде лице.";
        string cipher13 = Caesar.Encrypt(original13, 21);
        string decrypted13 = Caesar.Decrypt(cipher13, 21);

        Console.WriteLine($"Оригінальний текст:\n{original13}");
        Console.WriteLine($"Зашифровано (k=21):\n{cipher13}");
        Console.WriteLine($"Розшифровано:\n{decrypted13}");
        Console.WriteLine($"Збіг: {original13 == decrypted13}");
    }
}

/// <summary>
/// Аліас для класу Caesar за альтернативним правописом Ceasar.
/// </summary>
public class Ceasar : Caesar
{
}

