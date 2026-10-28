using System;
using System.Collections.Generic;
using System.Text;

public class OneTimePad
{
    // Таблиця стиснення (straddling checkerboard) для української абетки
    // Рядок 0 (без префіксу): 1:А, 2:И, 3:Т, 4:Е, 5:С, 6:Н, 7:О
    // Рядок 8: 81:Б, 82:В, 83:Г, 84:Ґ, 85:Д, 86:Є, 87:Ж, 88:З, 89:І, 80:Ї
    // Рядок 9: 91:Й, 92:К, 93:Л, 94:М, 95:П, 96:Р, 97:У, 98:Ф, 99:Х, 90:Ц
    // Рядок 0: 01:Ч, 02:Ш, 03:Щ, 04:Ь, 05:Ю, 06:Я, 07:' ' (пробіл)
    private static readonly Dictionary<char, string> CharToCode = new()
    {
        ['А'] = "1",  ['И'] = "2",  ['Т'] = "3",  ['Е'] = "4",  ['С'] = "5",  ['Н'] = "6",  ['О'] = "7",
        ['Б'] = "81", ['В'] = "82", ['Г'] = "83", ['Ґ'] = "84", ['Д'] = "85", ['Є'] = "86", ['Ж'] = "87", ['З'] = "88", ['І'] = "89", ['Ї'] = "80",
        ['Й'] = "91", ['К'] = "92", ['Л'] = "93", ['М'] = "94", ['П'] = "95", ['Р'] = "96", ['У'] = "97", ['Ф'] = "98", ['Х'] = "99", ['Ц'] = "90",
        ['Ч'] = "01", ['Ш'] = "02", ['Щ'] = "03", ['Ь'] = "04", ['Ю'] = "05", ['Я'] = "06", [' '] = "07"
    };

    private static readonly Dictionary<string, char> CodeToChar = new();

    static OneTimePad()
    {
        foreach (var kvp in CharToCode)
        {
            CodeToChar[kvp.Value] = kvp.Key;
        }
    }

    /// <summary>
    /// Перетворює текст у послідовність цифр за таблицею стиснення (straddling checkerboard).
    /// </summary>
    public static string EncodeToDigits(string text)
    {
        if (text == null) throw new ArgumentNullException(nameof(text));
        var sb = new StringBuilder();
        foreach (char c in text.ToUpperInvariant())
        {
            if (CharToCode.TryGetValue(c, out string? code))
            {
                sb.Append(code);
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Відновлює текст із послідовності цифр за таблицею стиснення.
    /// </summary>
    public static string DecodeFromDigits(string digits)
    {
        if (digits == null) throw new ArgumentNullException(nameof(digits));
        var sb = new StringBuilder();
        int i = 0;
        while (i < digits.Length)
        {
            char first = digits[i];
            if (first == '8' || first == '9' || first == '0')
            {
                if (i + 1 < digits.Length)
                {
                    string code = digits.Substring(i, 2);
                    if (CodeToChar.TryGetValue(code, out char c))
                    {
                        sb.Append(c);
                    }
                    else
                    {
                        sb.Append($"[{code}?]");
                    }
                    i += 2;
                }
                else
                {
                    sb.Append($"[{first}?]");
                    i++;
                }
            }
            else
            {
                string code = first.ToString();
                if (CodeToChar.TryGetValue(code, out char c))
                {
                    sb.Append(c);
                }
                else
                {
                    sb.Append($"[{code}?]");
                }
                i++;
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Додавання по модулю 10 відкритих цифр та цифр ключа: (P + K) mod 10.
    /// Ключ повторюється циклічно на всю довжину тексту.
    /// </summary>
    public static string EncryptDigits(string plainDigits, string keyDigits)
    {
        if (plainDigits == null) throw new ArgumentNullException(nameof(plainDigits));
        if (string.IsNullOrEmpty(keyDigits)) throw new ArgumentException("Ключ не може бути порожнім", nameof(keyDigits));

        var sb = new StringBuilder(plainDigits.Length);
        for (int i = 0; i < plainDigits.Length; i++)
        {
            int p = plainDigits[i] - '0';
            int k = keyDigits[i % keyDigits.Length] - '0';
            int c = (p + k) % 10;
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Віднімання по модулю 10 цифр ключа від шифрованих цифр: (C - K + 10) mod 10.
    /// Ключ повторюється циклічно на всю довжину шифротексту.
    /// </summary>
    public static string DecryptDigits(string cipherDigits, string keyDigits)
    {
        if (cipherDigits == null) throw new ArgumentNullException(nameof(cipherDigits));
        if (string.IsNullOrEmpty(keyDigits)) throw new ArgumentException("Ключ не може бути порожнім", nameof(keyDigits));

        var sb = new StringBuilder(cipherDigits.Length);
        for (int i = 0; i < cipherDigits.Length; i++)
        {
            int c = cipherDigits[i] - '0';
            int k = keyDigits[i % keyDigits.Length] - '0';
            int p = (c - k + 10) % 10;
            sb.Append(p);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Повне шифрування відкритого тексту за допомогою ключа (текстового або цифрового).
    /// Повертає цифровий шифротекст.
    /// </summary>
    public static string Encrypt(string plainText, string key)
    {
        string plainDigits = EncodeToDigits(plainText);
        string keyDigits = IsAllDigits(key) ? key : EncodeToDigits(key);
        return EncryptDigits(plainDigits, keyDigits);
    }

    /// <summary>
    /// Повне дешифрування цифрового шифротексту за допомогою ключа (текстового або цифрового).
    /// Повертає розшифрований відкритий текст.
    /// </summary>
    public static string Decrypt(string cipherDigits, string key)
    {
        string keyDigits = IsAllDigits(key) ? key : EncodeToDigits(key);
        string plainDigits = DecryptDigits(cipherDigits, keyDigits);
        return DecodeFromDigits(plainDigits);
    }

    private static bool IsAllDigits(string str)
    {
        if (string.IsNullOrEmpty(str)) return false;
        foreach (char c in str)
        {
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length >= 3)
        {
            string command = args[0].ToLowerInvariant();
            string input = args[1];
            string key = args[2];

            if (command == "encrypt" || command == "enc" || command == "e")
            {
                string plainDigits = EncodeToDigits(input);
                string keyDigits = IsAllDigits(key) ? key : EncodeToDigits(key);
                string cipher = EncryptDigits(plainDigits, keyDigits);
                Console.WriteLine($"Цифровий вираз тексту: {plainDigits}");
                Console.WriteLine($"Цифровий вираз ключа:  {keyDigits}");
                Console.WriteLine($"Шифротекст (mod 10):   {cipher}");
                return;
            }
            if (command == "decrypt" || command == "dec" || command == "d")
            {
                string keyDigits = IsAllDigits(key) ? key : EncodeToDigits(key);
                string plainDigits = DecryptDigits(input, keyDigits);
                string text = DecodeFromDigits(plainDigits);
                Console.WriteLine($"Цифровий вираз ключа: {keyDigits}");
                Console.WriteLine($"Відкриті цифри:       {plainDigits}");
                Console.WriteLine($"Розшифрований текст:  {text}");
                return;
            }
        }

        Console.WriteLine("==================================================");
        Console.WriteLine("    ПРОГРАМА: ОДНОРАЗОВИЙ БЛОКНОТ (OTP) (.NET)");
        Console.WriteLine("==================================================");

        // Демонстрація Завдання 4: Варіант 16 (Чуваєв А. О., рядок 6, остання цифра 6, ключ "пол")
        Console.WriteLine("\n--- ЗАВДАННЯ 4: ВАРІАНТ 16: Чуваєв А. О. (Рядок 6, Ключ: \"пол\") ---");
        string cipherZ4_16 = "89479925747754451753658367718929";
        string keyZ4_16 = "пол";
        string keyDigits16 = EncodeToDigits(keyZ4_16);
        string plainDigits16 = DecryptDigits(cipherZ4_16, keyDigits16);
        string text16 = DecodeFromDigits(plainDigits16);
        string reCipher16 = EncryptDigits(plainDigits16, keyDigits16);

        Console.WriteLine($"Шифротекст:           {cipherZ4_16}");
        Console.WriteLine($"Ключ:                 \"{keyZ4_16}\" -> цифри: {keyDigits16}");
        Console.WriteLine($"Відкриті цифри:       {plainDigits16}");
        Console.WriteLine($"Розшифрований текст:  {text16}");
        Console.WriteLine($"Перевірка шифрування: {cipherZ4_16 == reCipher16}");

        // Демонстрація Завдання 4: Варіант 13 (Світенко С. М., рядок 3, остання цифра 3, ключ "три")
        Console.WriteLine("\n--- ЗАВДАННЯ 4: ВАРІАНТ 13: Світенко С. М. (Рядок 3, Ключ: \"три\") ---");
        string cipherZ4_13 = "2330993010441478992202587248";
        string keyZ4_13 = "три";
        string keyDigits13 = EncodeToDigits(keyZ4_13);
        string plainDigits13 = DecryptDigits(cipherZ4_13, keyDigits13);
        string text13 = DecodeFromDigits(plainDigits13);
        string reCipher13 = EncryptDigits(plainDigits13, keyDigits13);

        Console.WriteLine($"Шифротекст:           {cipherZ4_13}");
        Console.WriteLine($"Ключ:                 \"{keyZ4_13}\" -> цифри: {keyDigits13}");
        Console.WriteLine($"Відкриті цифри:       {plainDigits13}");
        Console.WriteLine($"Розшифрований текст:  {text13}");
        Console.WriteLine($"Перевірка шифрування: {cipherZ4_13 == reCipher13}");

        // Демонстрація Завдання 5 & 6 (Бригада двох студентів)
        Console.WriteLine("\n==================================================");
        Console.WriteLine("    ЗАВДАННЯ 5 & 6: СПІЛЬНА РОБОТА БРИГАДИ");
        Console.WriteLine("==================================================");

        // Студент 1 (Артем, вар. 16 -> завдання 4: Довільний текст довжиною до 70 символів)
        Console.WriteLine("\n[Студент 1 (Чуваєв А. О., вар. 16)] -> Завдання 5.4:");
        string textZ5_1 = "БЕЗПЕКА ПРОГРАМ ТА ДАНИХ ПРАКТИЧНЕ ЗАНЯТТЯ ОДИН";
        string keyZ5_1 = "АРТЕМ КРИПТОГРАФІЯ";
        string cipherDigitsZ5_1 = OneTimePad.Encrypt(textZ5_1, keyZ5_1);
        Console.WriteLine($"Текст: {textZ5_1}");
        Console.WriteLine($"Ключ:  {keyZ5_1} (цифри: {EncodeToDigits(keyZ5_1)})");
        Console.WriteLine($"Зашифровані цифри: {cipherDigitsZ5_1}");

        // Студент 2 (Софія, вар. 13 -> завдання 3: Назва та дата свята власним ім'ям)
        Console.WriteLine("\n[Студент 2 (Світенко С. М., вар. 13)] -> Завдання 5.3:");
        string textZ5_2 = "ДЕНЬ НЕЗАЛЕЖНОСТІ ДВАДЦЯТЬ ЧЕТВЕРТЕ СЕРПНЯ";
        string keyZ5_2 = "СОФІЯ";
        string cipherDigitsZ5_2 = OneTimePad.Encrypt(textZ5_2, keyZ5_2);
        Console.WriteLine($"Текст: {textZ5_2}");
        Console.WriteLine($"Ключ:  {keyZ5_2} (цифри: {EncodeToDigits(keyZ5_2)})");
        Console.WriteLine($"Зашифровані цифри: {cipherDigitsZ5_2}");

        // Завдання 6: Взаємний обмін та розшифрування
        Console.WriteLine("\n[Завдання 6: Взаємний обмін]");
        string decFromStudent2 = OneTimePad.Decrypt(cipherDigitsZ5_2, keyZ5_2);
        string decFromStudent1 = OneTimePad.Decrypt(cipherDigitsZ5_1, keyZ5_1);

        Console.WriteLine($"Студент 1 (Артем) розшифрував повідомлення Студента 2 (Софії):\n\"{decFromStudent2}\" (Збіг: {textZ5_2 == decFromStudent2})");
        Console.WriteLine($"Студент 2 (Софія) розшифрувала повідомлення Студента 1 (Артема):\n\"{decFromStudent1}\" (Збіг: {textZ5_1 == decFromStudent1})");
    }
}
