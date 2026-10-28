using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

public class Client
{
    public const string DefaultHost = "127.0.0.1";
    public const int DefaultPort = 5005;

    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        string host = args.Length > 0 ? args[0] : DefaultHost;
        int port = args.Length > 1 && int.TryParse(args[1], out int p) ? p : DefaultPort;

        Console.WriteLine("==================================================");
        Console.WriteLine("   КЛІЄНТ БЕЗПЕЧНОГО ОБМІНУ (OTP NETWORK CLIENT)");
        Console.WriteLine("   Кафедра ПІ, ХНУРЕ — Практичне заняття №2");
        Console.WriteLine("==================================================");

        // Якщо передано аргументи:
        // dotnet run Client.cs -- 127.0.0.1 5005 "Повідомлення" "Straddling_Mod10"
        if (args.Length >= 3)
        {
            string message = args[2];
            string mode = args.Length > 3 ? args[3] : "Straddling_Mod10";
            SendMessage(host, port, "Чуваєв А. О. (вар. 16)", message, mode);
            return;
        }

        // Демонстраційний сценарій для бригади двох студентів:
        Console.WriteLine("\n[1] Демонстрація 1: Передача повідомлення в класичному режимі (Straddling Checkerboard + Mod10)");
        string msg1 = "ПРИВІТ ВІД АРТЕМА ЧУВАЄВА. ВАРІАНТ ШІСТНАДЦЯТЬ. ЗАХИЩЕНИЙ КАНАЛ ЗВ'ЯЗКУ ПРАЦЮЄ!";
        SendMessage(host, port, "Чуваєв А. О. (вар. 16)", msg1, "Straddling_Mod10");

        Console.WriteLine("\n--------------------------------------------------");
        Console.WriteLine("[2] Демонстрація 2: Передача повідомлення в машинному режимі (UTF-8 Bytes + XOR)");
        string msg2 = "Світенко Софія (вар. 13): підтверджую готовність бригади до захисту ПЗ №2!";
        SendMessage(host, port, "Світенко С. М. (вар. 13)", msg2, "Machine_XOR");
    }

    public static void SendMessage(string host, int port, string senderName, string plainText, string mode)
    {
        Console.WriteLine($"\n[*] Підключення до сервера {host}:{port}...");

        using var client = new TcpClient();
        try
        {
            client.Connect(host, port);
            Console.WriteLine("[+] З'єднання з сервером успішно встановлено.");

            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            using var writer = new StreamWriter(stream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };

            // Шифрування повідомлення за схемою One-Time Pad
            Console.WriteLine($"\n--- [ШИФРУВАННЯ ВІДПРАВНИКОМ: {senderName}] ---");
            Console.WriteLine($"Відкритий текст: \"{plainText}\"");
            Console.WriteLine($"Обраний режим:   {mode}");

            string cipher = "";
            string key = "";

            if (mode == "Straddling_Mod10")
            {
                (cipher, key) = OneTimePadCore.EncryptMod10(plainText);
            }
            else
            {
                (cipher, key) = OneTimePadCore.EncryptXor(plainText);
            }

            Console.WriteLine($"Ключ блокноту:   {key}");
            Console.WriteLine($"Шифротекст:      {cipher}");

            var packet = new NetworkPacket
            {
                Sender = senderName,
                Mode = mode,
                CipherData = cipher,
                KeyData = key,
                Timestamp = DateTime.UtcNow
            };

            // Відправка зашифрованого повідомлення через сокет
            packet.WriteTo(writer);
            Console.WriteLine("[>] Зашифрований пакет передано в мережевий сокет.");

            // Очікування зашифрованої відповіді від сервера
            Console.WriteLine("[*] Очікування зашифрованої відповіді від сервера...");
            var responsePacket = NetworkPacket.ReadFrom(reader);
            if (responsePacket == null)
            {
                Console.WriteLine("[-] Відповідь не надійшла (сервер закрив з'єднання).");
                return;
            }

            Console.WriteLine("\n--- [ОТРИМАНО ЗАШИФРОВАНУ ВІДПОВІДЬ З МЕРЕЖІ] ---");
            Console.WriteLine($"Відправник:      {responsePacket.Sender}");
            Console.WriteLine($"Шифротекст:      {responsePacket.CipherData}");
            Console.WriteLine($"Ключ відповіді:  {responsePacket.KeyData}");

            string decryptedReply = "";
            if (responsePacket.Mode == "Straddling_Mod10")
            {
                decryptedReply = OneTimePadCore.DecryptMod10(responsePacket.CipherData, responsePacket.KeyData);
            }
            else
            {
                decryptedReply = OneTimePadCore.DecryptXor(responsePacket.CipherData, responsePacket.KeyData);
            }

            Console.WriteLine($"--> РОЗШИФРОВАНА ВІДПОВІДЬ:\n    \"{decryptedReply}\"");
            Console.WriteLine("[+] Обмін даними успішно завершено.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Помилка з'єднання: {ex.Message}");
        }
    }
}

public class NetworkPacket
{
    public string Sender { get; set; } = "";
    public string Mode { get; set; } = "Straddling_Mod10";
    public string CipherData { get; set; } = "";
    public string KeyData { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public void WriteTo(StreamWriter writer)
    {
        writer.WriteLine(Sender);
        writer.WriteLine(Mode);
        writer.WriteLine(CipherData);
        writer.WriteLine(KeyData);
        writer.WriteLine(Timestamp.ToString("o"));
    }

    public static NetworkPacket? ReadFrom(StreamReader reader)
    {
        string? sender = reader.ReadLine();
        if (sender == null) return null;
        string mode = reader.ReadLine() ?? "";
        string cipher = reader.ReadLine() ?? "";
        string key = reader.ReadLine() ?? "";
        string ts = reader.ReadLine() ?? "";
        return new NetworkPacket
        {
            Sender = sender,
            Mode = mode,
            CipherData = cipher,
            KeyData = key,
            Timestamp = DateTime.TryParse(ts, out var t) ? t : DateTime.UtcNow
        };
    }
}

public static class OneTimePadCore
{
    private static readonly Dictionary<char, string> CharToCode = new()
    {
        ['А'] = "1",  ['И'] = "2",  ['Т'] = "3",  ['Е'] = "4",  ['С'] = "5",  ['Н'] = "6",  ['О'] = "7",
        ['Б'] = "81", ['В'] = "82", ['Г'] = "83", ['Ґ'] = "84", ['Д'] = "85", ['Є'] = "86", ['Ж'] = "87", ['З'] = "88", ['І'] = "89", ['Ї'] = "80",
        ['Й'] = "91", ['К'] = "92", ['Л'] = "93", ['М'] = "94", ['П'] = "95", ['Р'] = "96", ['У'] = "97", ['Ф'] = "98", ['Х'] = "99", ['Ц'] = "90",
        ['Ч'] = "01", ['Ш'] = "02", ['Щ'] = "03", ['Ь'] = "04", ['Ю'] = "05", ['Я'] = "06", [' '] = "07", ['.'] = "08", [','] = "09", ['!'] = "00",
        ['-'] = "021", ['?'] = "022", [':'] = "023", ['('] = "024", [')'] = "025", ['['] = "026", [']'] = "027", ['"'] = "028"
    };

    private static readonly Dictionary<string, char> CodeToChar = new();

    static OneTimePadCore()
    {
        foreach (var kvp in CharToCode)
            CodeToChar[kvp.Value] = kvp.Key;
    }

    public static string EncodeToDigits(string text)
    {
        var sb = new StringBuilder();
        foreach (char c in text.ToUpperInvariant())
        {
            if (CharToCode.TryGetValue(c, out string? code))
                sb.Append(code);
            else if (c == '\'')
                continue;
        }
        return sb.ToString();
    }

    public static string DecodeFromDigits(string digits)
    {
        var sb = new StringBuilder();
        int i = 0;
        while (i < digits.Length)
        {
            char first = digits[i];
            if (first == '8' || first == '9')
            {
                if (i + 1 < digits.Length && CodeToChar.TryGetValue(digits.Substring(i, 2), out char c))
                {
                    sb.Append(c);
                    i += 2;
                }
                else i++;
            }
            else if (first == '0')
            {
                if (i + 2 < digits.Length && CodeToChar.TryGetValue(digits.Substring(i, 3), out char c3))
                {
                    sb.Append(c3);
                    i += 3;
                }
                else if (i + 1 < digits.Length && CodeToChar.TryGetValue(digits.Substring(i, 2), out char c2))
                {
                    sb.Append(c2);
                    i += 2;
                }
                else i++;
            }
            else
            {
                if (CodeToChar.TryGetValue(first.ToString(), out char c))
                    sb.Append(c);
                i++;
            }
        }
        return sb.ToString();
    }

    public static (string Cipher, string Key) EncryptMod10(string plainText, string? preSharedKey = null)
    {
        string pDigits = EncodeToDigits(plainText);
        string kDigits;
        if (string.IsNullOrEmpty(preSharedKey))
        {
            kDigits = GenerateRandomDigits(pDigits.Length);
        }
        else
        {
            kDigits = IsAllDigits(preSharedKey) ? preSharedKey : EncodeToDigits(preSharedKey);
        }

        var sb = new StringBuilder(pDigits.Length);
        for (int i = 0; i < pDigits.Length; i++)
        {
            int p = pDigits[i] - '0';
            int k = kDigits[i % kDigits.Length] - '0';
            sb.Append((p + k) % 10);
        }
        return (sb.ToString(), kDigits);
    }

    public static string DecryptMod10(string cipherDigits, string key)
    {
        string kDigits = IsAllDigits(key) ? key : EncodeToDigits(key);
        var sb = new StringBuilder(cipherDigits.Length);
        for (int i = 0; i < cipherDigits.Length; i++)
        {
            int c = cipherDigits[i] - '0';
            int k = kDigits[i % kDigits.Length] - '0';
            sb.Append((c - k + 10) % 10);
        }
        return DecodeFromDigits(sb.ToString());
    }

    public static (string CipherBase64, string KeyBase64) EncryptXor(string plainText)
    {
        byte[] pBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] kBytes = new byte[pBytes.Length];
        RandomNumberGenerator.Fill(kBytes);

        byte[] cBytes = new byte[pBytes.Length];
        for (int i = 0; i < pBytes.Length; i++)
        {
            cBytes[i] = (byte)(pBytes[i] ^ kBytes[i]);
        }
        return (Convert.ToBase64String(cBytes), Convert.ToBase64String(kBytes));
    }

    public static string DecryptXor(string cipherBase64, string keyBase64)
    {
        byte[] cBytes = Convert.FromBase64String(cipherBase64);
        byte[] kBytes = Convert.FromBase64String(keyBase64);

        byte[] pBytes = new byte[cBytes.Length];
        for (int i = 0; i < cBytes.Length; i++)
        {
            pBytes[i] = (byte)(cBytes[i] ^ kBytes[i % kBytes.Length]);
        }
        return Encoding.UTF8.GetString(pBytes);
    }

    private static string GenerateRandomDigits(int length)
    {
        byte[] bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            sb.Append(bytes[i] % 10);
        }
        return sb.ToString();
    }

    private static bool IsAllDigits(string str)
    {
        if (string.IsNullOrEmpty(str)) return false;
        foreach (char c in str) if (c < '0' || c > '9') return false;
        return true;
    }
}
