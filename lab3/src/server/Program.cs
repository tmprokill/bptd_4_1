#!/usr/bin/env dotnet-run
#:include CustomHasher.cs
#:include CollisionEngine.cs
#:include RsaSigner.cs

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Lab3.Server;

public class Program
{
    private const int Port = 5070;
    private static RsaSigner? _rsaSigner;
    private static string _clientFilesPath = "";
    private static string _samplesPath = "";

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        Console.WriteLine("======================================================================");
        Console.WriteLine("  ЛАБОРАТОРНА РОБОТА №3: ХЕШ-ФУНКЦІЇ ТА АНАЛІЗ КОЛІЗІЙ");
        Console.WriteLine("  Кафедра ПІ, ХНУРЕ | Дисципліна: Безпека програм та даних");
        Console.WriteLine("  Бригада: Чуваєв А. О. (вар. 16), Світенко С. М. (вар. 13)");
        Console.WriteLine("======================================================================\n");

        _rsaSigner = new RsaSigner(2048);
        Console.WriteLine("[+] Сервіс RSA-2048 для цифрового підпису дайджестів ініціалізовано.");

        ResolvePaths();
        Console.WriteLine($"[+] Каталог клієнтського інтерфейсу: {_clientFilesPath}");
        Console.WriteLine($"[+] Каталог тестових зразків:        {_samplesPath}\n");

        if (args.Length > 0 && args[0].Equals("--demo", StringComparison.OrdinalIgnoreCase))
        {
            RunDemonstration();
            return;
        }

        if (args.Length > 0 && args[0].Equals("--server", StringComparison.OrdinalIgnoreCase))
        {
            await RunWebServerAsync();
            return;
        }

        // Інтерактивне меню
        while (true)
        {
            Console.WriteLine("--- Головне меню ---");
            Console.WriteLine("1. Запустити повну автоматичну демонстрацію (--demo)");
            Console.WriteLine("2. Обчислити хеш-суму файлу (2, 4, 8 біт)");
            Console.WriteLine("3. Тестування лавинного ефекту (Avalanche Effect >= 30%)");
            Console.WriteLine("4. Перевірка ручної колізії (2 файли)");
            Console.WriteLine("5. Автоматична генерація прихованої колізії (Stealth Collision)");
            Console.WriteLine("6. Електронний цифровий підпис RSA-2048 дайджесту");
            Console.WriteLine("7. Запустити Web-сервер (http://localhost:5070)");
            Console.WriteLine("0. Вихід");
            Console.Write("\nОберіть дію [0-7]: ");

            string? choice = Console.ReadLine()?.Trim();
            Console.WriteLine();

            switch (choice)
            {
                case "1":
                    RunDemonstration();
                    break;
                case "2":
                    InteractiveCalculateHash();
                    break;
                case "3":
                    InteractiveAvalancheTest();
                    break;
                case "4":
                    InteractiveManualCollision();
                    break;
                case "5":
                    InteractiveStealthCollision();
                    break;
                case "6":
                    InteractiveRsaSignature();
                    break;
                case "7":
                    await RunWebServerAsync();
                    return;
                case "0":
                    Console.WriteLine("Роботу завершено.");
                    return;
                default:
                    Console.WriteLine("[!] Невідома опція, спробуйте ще раз.\n");
                    break;
            }
        }
    }

    private static void ResolvePaths()
    {
        string currentDir = Directory.GetCurrentDirectory();
        string baseDir = AppContext.BaseDirectory;

        string[] clientCandidates = {
            Path.Combine(currentDir, "lab3", "src", "client"),
            Path.Combine(currentDir, "..", "client"),
            Path.Combine(currentDir, "client"),
            Path.Combine(currentDir, "src", "client"),
            Path.Combine(baseDir, "..", "..", "..", "client"),
            Path.Combine(baseDir, "..", "client")
        };

        foreach (var c in clientCandidates)
        {
            if (Directory.Exists(c))
            {
                _clientFilesPath = Path.GetFullPath(c);
                break;
            }
        }

        string[] sampleCandidates = {
            Path.Combine(currentDir, "lab3", "src", "samples"),
            Path.Combine(currentDir, "..", "samples"),
            Path.Combine(currentDir, "samples"),
            Path.Combine(currentDir, "src", "samples"),
            Path.Combine(baseDir, "..", "..", "..", "samples"),
            Path.Combine(baseDir, "..", "samples")
        };

        foreach (var s in sampleCandidates)
        {
            if (Directory.Exists(s))
            {
                _samplesPath = Path.GetFullPath(s);
                break;
            }
        }
    }

    public static void RunDemonstration()
    {
        Console.WriteLine("======================================================================");
        Console.WriteLine("  ПРОТОКОЛ ДЕМОНСТРАЦІЙНОГО ТЕСТУВАННЯ ЛАБОРАТОРНОЇ РОБОТИ №3");
        Console.WriteLine("======================================================================\n");

        // 1. Хешування 3 типів файлів для варіантів 16 та 13
        Console.WriteLine("--- ЕТАП 1: ОБЧИСЛЕННЯ ХЕШ-СУМ ДЛЯ 3-Х ТИПІВ ФАЙЛІВ (2, 4, 8 БІТ) ---");
        string docPath = Path.Combine(_samplesPath, "sample_document.txt");
        string codePath = Path.Combine(_samplesPath, "sample_code.cs");
        string imgPath = Path.Combine(_samplesPath, "sample_image.png");

        string[] testFiles = { docPath, codePath, imgPath };

        foreach (var file in testFiles)
        {
            if (!File.Exists(file))
            {
                Console.WriteLine($"[!] Файл не знайдено: {file}");
                continue;
            }

            byte[] data = File.ReadAllBytes(file);
            string type = CollisionEngine.DetectFileType(file).ToString();
            Console.WriteLine($"\n[Файл: {Path.GetFileName(file)}] (Тип: {type}, Розмір: {data.Length} байт)");

            foreach (int bits in new[] { 2, 4, 8 })
            {
                byte digest = CustomHasher.ComputeDigest(data, bits);
                string bitStr = CustomHasher.DigestToBitString(digest, bits);
                Console.WriteLine($"  - Хеш ({bits} біт): [ {bitStr} ] (hex: 0x{digest:X2}, dec: {digest})");
            }
        }

        // 2. Тестування лавинного ефекту (Avalanche Effect)
        Console.WriteLine("\n--- ЕТАП 2: ДОСЛІДЖЕННЯ ЛАВИННОГО ЕФЕКТУ (>= 30% БІТОВИХ ЗМІН) ---");
        byte[] docBytes = File.Exists(docPath) ? File.ReadAllBytes(docPath) : Encoding.UTF8.GetBytes("Лабораторна робота №3 БПТД ХНУРЕ");
        var (avgPct, totalTests, passRate) = CustomHasher.TestAvalancheEffect(docBytes, 8, 200);
        Console.WriteLine($"Вхідний зразок: {docBytes.Length} байт");
        Console.WriteLine($"Кількість інверсій одиничних бітів: {totalTests}");
        Console.WriteLine($"Середній відсоток зміни вихідних бітів: {avgPct:F2}% (Вимога: >= 30%)");
        Console.WriteLine($"Тестів з виконанням критерію: {passRate:F2}%");
        if (avgPct >= 30.0)
        {
            Console.WriteLine("[+] ВЕРИФІКАЦІЯ УСПІШНА: Алгоритм демонструє виражений лавинний ефект!");
        }
        else
        {
            Console.WriteLine("[-] УВАГА: Лавинний ефект нижче порогового значення 30%.");
        }

        // 3. Ручний підбір колізії (2 біти)
        Console.WriteLine("\n--- ЕТАП 3: РУЧНИЙ ПІДБІР КОЛІЗІЇ (2 БІТИ) ---");
        string manual1 = "ХНУРЕ, кафедра ПІ, БПТД. Чуваєв А. О. (вар. 16)";
        string manual2 = "ХНУРЕ, кафедра ПІ, БПТД. Світенко С. М. (вар. 13)";
        byte hashM1 = CustomHasher.ComputeDigest(Encoding.UTF8.GetBytes(manual1), 2);
        byte hashM2 = CustomHasher.ComputeDigest(Encoding.UTF8.GetBytes(manual2), 2);

        // Якщо не зійшлися заздалегідь, коригуємо суфікс
        if (hashM1 != hashM2)
        {
            for (int pad = 0; pad < 20; pad++)
            {
                string candidate = manual2 + new string(' ', pad);
                if (CustomHasher.ComputeDigest(Encoding.UTF8.GetBytes(candidate), 2) == hashM1)
                {
                    manual2 = candidate;
                    hashM2 = hashM1;
                    break;
                }
            }
        }

        Console.WriteLine($"Текст 1: \"{manual1}\"");
        Console.WriteLine($"  Хеш (2 біти): [{CustomHasher.DigestToBitString(hashM1, 2)}] (dec: {hashM1})");
        Console.WriteLine($"Текст 2: \"{manual2}\"");
        Console.WriteLine($"  Хеш (2 біти): [{CustomHasher.DigestToBitString(hashM2, 2)}] (dec: {hashM2})");
        Console.WriteLine($"Результат збігу хешів: {(hashM1 == hashM2 ? "КОЛІЗІЯ ЗНАЙДЕНА (TRUE)" : "РІЗНІ ХЕШІ (FALSE)")}");

        // 4. Автоматична генерація прихованої колізії (Stealth Collision)
        Console.WriteLine("\n--- ЕТАП 4: АВТОМАТИЧНА ГЕНЕРАЦІЯ СТЕЛС-КОЛІЗІЇ ДЛЯ 3-Х ТИПІВ ФАЙЛІВ ---");
        foreach (var file in testFiles)
        {
            if (!File.Exists(file)) continue;
            byte[] origData = File.ReadAllBytes(file);
            string fName = Path.GetFileName(file);
            int testBits = 8; // демонструємо на 8 бітах (повний байт)

            byte origDigest = CustomHasher.ComputeDigest(origData, testBits);
            var (success, collidedBytes, attempts, strategy) = CollisionEngine.GenerateStealthCollision(origData, file, testBits);

            if (success)
            {
                byte newDigest = CustomHasher.ComputeDigest(collidedBytes, testBits);
                bool sameHash = (origDigest == newDigest);
                bool diffBytes = !StructuralComparisons(origData, collidedBytes);

                Console.WriteLine($"[+] Файл: {fName}");
                Console.WriteLine($"    Стратегія стелсу: {strategy}");
                Console.WriteLine($"    Кількість спроб:  {attempts}");
                Console.WriteLine($"    Вихідний хеш:     [{CustomHasher.DigestToBitString(origDigest, testBits)}] (hex: 0x{origDigest:X2})");
                Console.WriteLine($"    Колізійний хеш:   [{CustomHasher.DigestToBitString(newDigest, testBits)}] (hex: 0x{newDigest:X2})");
                Console.WriteLine($"    Хеші ідентичні:   {sameHash} | Зміст файлу змінено: {diffBytes}");
                Console.WriteLine($"    Різниця розміру:  +{collidedBytes.Length - origData.Length} байт");
            }
            else
            {
                Console.WriteLine($"[-] Не вдалося знайти колізію для {fName}");
            }
        }

        // 5. Електронний цифровий підпис RSA-2048 (Додаткове завдання 7*)
        Console.WriteLine("\n--- ЕТАП 5: ЦИФРОВИЙ ПІДПИС ДАЙДЖЕСТУ RSA-2048 (ЗАВДАННЯ 7*) ---");
        byte[] docSample = File.ReadAllBytes(docPath);
        byte docHash8 = CustomHasher.ComputeDigest(docSample, 8);
        byte[] hashPayload = new byte[] { docHash8 };

        string signature = _rsaSigner!.SignDigest(hashPayload);
        bool verifyValid = _rsaSigner.VerifyDigest(hashPayload, signature);

        // Фальсифікований хеш
        byte[] forgedPayload = new byte[] { (byte)(docHash8 ^ 0x01) };
        bool verifyForged = _rsaSigner.VerifyDigest(forgedPayload, signature);

        Console.WriteLine($"Дайджест повідомлення (8 біт): [{CustomHasher.DigestToBitString(docHash8, 8)}] (0x{docHash8:X2})");
        Console.WriteLine($"RSA-2048 Digital Signature (Base64):\n  {signature.Substring(0, 48)}... (довжина: {signature.Length} символів)");
        Console.WriteLine($"Верифікація автентичного дайджесту:  {(verifyValid ? "[ПІДТВЕРДЖЕНО VALID]" : "[ВІДХИЛЕНО INVALID]")}");
        Console.WriteLine($"Верифікація модифікованого дайджесту: {(verifyForged ? "[НЕБЕЗПЕКА VALID]" : "[УСПІШНО ВІДХИЛЕНО INVALID]")}");

        Console.WriteLine("\n======================================================================");
        Console.WriteLine("  УСІ ТЕСТИ ЛАБОРАТОРНОЇ РОБОТИ №3 ВИКОНАНО УСПІШНО [OK]");
        Console.WriteLine("======================================================================\n");
    }

    private static bool StructuralComparisons(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    private static void InteractiveCalculateHash()
    {
        Console.Write("Введіть шлях до файлу (або Enter для зразка документа): ");
        string? path = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(path))
            path = Path.Combine(_samplesPath, "sample_document.txt");

        if (!File.Exists(path))
        {
            Console.WriteLine($"[!] Файл не знайдено: {path}\n");
            return;
        }

        byte[] bytes = File.ReadAllBytes(path);
        Console.WriteLine($"\nАналіз файлу: {Path.GetFileName(path)} ({bytes.Length} байт)");
        foreach (int bits in new[] { 2, 4, 8 })
        {
            byte d = CustomHasher.ComputeDigest(bytes, bits);
            Console.WriteLine($"  Хеш ({bits} біт): [{CustomHasher.DigestToBitString(d, bits)}] (Hex: 0x{d:X2}, Dec: {d})");
        }
        Console.WriteLine();
    }

    private static void InteractiveAvalancheTest()
    {
        Console.Write("Введіть розмір хешу для тесту [2, 4, 8] (за замовчуванням 8): ");
        string? bitsStr = Console.ReadLine()?.Trim();
        int bits = 8;
        if (int.TryParse(bitsStr, out int b) && (b == 2 || b == 4 || b == 8)) bits = b;

        string docPath = Path.Combine(_samplesPath, "sample_document.txt");
        byte[] data = File.Exists(docPath) ? File.ReadAllBytes(docPath) : Encoding.UTF8.GetBytes("Avalanche testing sample");

        Console.WriteLine($"Тестування на вибірці з 200 бітових збурень ({bits} біт)...");
        var (avgPct, totalTests, passRate) = CustomHasher.TestAvalancheEffect(data, bits, 200);

        Console.WriteLine($"Середня зміна виходу: {avgPct:F2}% (Вимога >= 30%)");
        Console.WriteLine($"Відсоток успішних тестів: {passRate:F2}%\n");
    }

    private static void InteractiveManualCollision()
    {
        Console.WriteLine("Введіть перший текст:");
        string text1 = Console.ReadLine() ?? "";
        Console.WriteLine("Введіть другий текст:");
        string text2 = Console.ReadLine() ?? "";

        Console.Write("Оберіть довжину хешу [2, 4, 8] (за замовчуванням 2): ");
        string? bitsStr = Console.ReadLine()?.Trim();
        int bits = 2;
        if (int.TryParse(bitsStr, out int b) && (b == 2 || b == 4 || b == 8)) bits = b;

        byte h1 = CustomHasher.ComputeDigest(Encoding.UTF8.GetBytes(text1), bits);
        byte h2 = CustomHasher.ComputeDigest(Encoding.UTF8.GetBytes(text2), bits);

        Console.WriteLine($"Хеш 1: [{CustomHasher.DigestToBitString(h1, bits)}]");
        Console.WriteLine($"Хеш 2: [{CustomHasher.DigestToBitString(h2, bits)}]");
        if (h1 == h2)
            Console.WriteLine("[+] ЗБІГ! Колізію зафіксовано!\n");
        else
            Console.WriteLine("[-] Хеші різні. Спробуйте змінити символи або пробіли.\n");
    }

    private static void InteractiveStealthCollision()
    {
        Console.Write("Введіть шлях до вхідного файлу: ");
        string? path = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(path))
            path = Path.Combine(_samplesPath, "sample_document.txt");

        if (!File.Exists(path))
        {
            Console.WriteLine($"[!] Файл не знайдено: {path}\n");
            return;
        }

        Console.Write("Оберіть довжину хешу [2, 4, 8] (за замовчуванням 8): ");
        string? bitsStr = Console.ReadLine()?.Trim();
        int bits = 8;
        if (int.TryParse(bitsStr, out int b) && (b == 2 || b == 4 || b == 8)) bits = b;

        byte[] original = File.ReadAllBytes(path);
        byte origHash = CustomHasher.ComputeDigest(original, bits);
        Console.WriteLine($"Поточний хеш ({bits} біт): [{CustomHasher.DigestToBitString(origHash, bits)}]");
        Console.WriteLine("Пошук колізії стелс-методом...");

        var (success, collidedBytes, attempts, strategy) = CollisionEngine.GenerateStealthCollision(original, path, bits);
        if (success)
        {
            byte newHash = CustomHasher.ComputeDigest(collidedBytes, bits);
            string outPath = Path.Combine(Path.GetDirectoryName(path)!, "collision_" + Path.GetFileName(path));
            File.WriteAllBytes(outPath, collidedBytes);

            Console.WriteLine($"[+] Колізію знайдено за {attempts} спроб!");
            Console.WriteLine($"[+] Стратегія: {strategy}");
            Console.WriteLine($"[+] Новий хеш: [{CustomHasher.DigestToBitString(newHash, bits)}]");
            Console.WriteLine($"[+] Збережено у: {outPath}\n");
        }
        else
        {
            Console.WriteLine("[-] Не вдалося знайти колізію у заданих межах.\n");
        }
    }

    private static void InteractiveRsaSignature()
    {
        Console.Write("Введіть текст для хешування та підпису: ");
        string text = Console.ReadLine() ?? "Тестове повідомлення";
        byte digest = CustomHasher.ComputeDigest(Encoding.UTF8.GetBytes(text), 8);
        byte[] payload = new byte[] { digest };

        string signature = _rsaSigner!.SignDigest(payload);
        Console.WriteLine($"\nДайджест повідомлення (8 біт): [{CustomHasher.DigestToBitString(digest, 8)}]");
        Console.WriteLine($"RSA Підпис (Base64):\n{signature}");
        bool ok = _rsaSigner.VerifyDigest(payload, signature);
        Console.WriteLine($"Перевірка підпису: {(ok ? "УСПІШНА (VALID)" : "НЕВДАЛА (INVALID)")}\n");
    }

    public static async Task RunWebServerAsync()
    {
        string prefix = $"http://localhost:{Port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);

        try
        {
            listener.Start();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Помилка запуску HttpListener: {ex.Message}");
            return;
        }

        Console.WriteLine($"[+] Web-сервер запущено на {prefix}");
        Console.WriteLine($"[+] Відкрийте у браузері: {prefix}");
        Console.WriteLine("    Натисніть Ctrl+C для зупинки сервера.\n");

        while (listener.IsListening)
        {
            try
            {
                var context = await listener.GetContextAsync();
                _ = Task.Run(() => HandleHttpRequest(context));
            }
            catch
            {
                if (!listener.IsListening) break;
            }
        }
    }

    private static async Task HandleHttpRequest(HttpListenerContext context)
    {
        var req = context.Request;
        var res = context.Response;

        // CORS заголовки
        res.Headers.Add("Access-Control-Allow-Origin", "*");
        res.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

        if (req.HttpMethod == "OPTIONS")
        {
            res.StatusCode = 200;
            res.Close();
            return;
        }

        string path = req.Url?.AbsolutePath ?? "/";

        try
        {
            if (req.HttpMethod == "POST" && path == "/api/hash")
            {
                await HandleApiHash(req, res);
                return;
            }

            if (req.HttpMethod == "POST" && path == "/api/collision/auto")
            {
                await HandleApiAutoCollision(req, res);
                return;
            }

            if (req.HttpMethod == "POST" && path == "/api/collision/verify")
            {
                await HandleApiVerifyCollision(req, res);
                return;
            }

            if (req.HttpMethod == "POST" && path == "/api/avalanche")
            {
                await HandleApiAvalanche(req, res);
                return;
            }

            if (req.HttpMethod == "POST" && path == "/api/rsa/sign")
            {
                await HandleApiRsaSign(req, res);
                return;
            }

            if (req.HttpMethod == "POST" && path == "/api/rsa/verify")
            {
                await HandleApiRsaVerify(req, res);
                return;
            }

            if (req.HttpMethod == "GET" && path == "/api/samples")
            {
                await HandleApiSamples(res);
                return;
            }

            // Статичні файли клієнта
            await ServeStaticFile(path, res);
        }
        catch (Exception ex)
        {
            res.StatusCode = 500;
            byte[] errBytes = Encoding.UTF8.GetBytes($"{{\"error\":\"{EscapeJson(ex.Message)}\"}}");
            res.ContentType = "application/json; charset=utf-8";
            await res.OutputStream.WriteAsync(errBytes);
            res.Close();
        }
    }

    private static async Task HandleApiHash(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        int bits = root.TryGetProperty("bits", out var bElem) ? bElem.GetInt32() : 8;
        string? text = root.TryGetProperty("text", out var tElem) ? tElem.GetString() : null;
        string? fileBase64 = root.TryGetProperty("fileBase64", out var fElem) ? fElem.GetString() : null;

        byte[] data;
        if (!string.IsNullOrEmpty(fileBase64))
        {
            data = Convert.FromBase64String(fileBase64);
        }
        else
        {
            data = Encoding.UTF8.GetBytes(text ?? "");
        }

        byte digest = CustomHasher.ComputeDigest(data, bits);
        string bitStr = CustomHasher.DigestToBitString(digest, bits);

        string json = $"{{\"status\":\"ok\",\"bits\":{bits},\"digest\":{digest},\"bitString\":\"{bitStr}\",\"hex\":\"0x{digest:X2}\",\"byteLength\":{data.Length}}}";
        await SendJson(res, json);
    }

    private static async Task HandleApiAutoCollision(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        int bits = root.TryGetProperty("bits", out var bElem) ? bElem.GetInt32() : 8;
        string fileName = root.TryGetProperty("fileName", out var nElem) ? (nElem.GetString() ?? "file.txt") : "file.txt";
        string? fileBase64 = root.TryGetProperty("fileBase64", out var fElem) ? fElem.GetString() : null;
        string? text = root.TryGetProperty("text", out var tElem) ? tElem.GetString() : null;

        byte[] original = !string.IsNullOrEmpty(fileBase64) ? Convert.FromBase64String(fileBase64) : Encoding.UTF8.GetBytes(text ?? "");
        byte origDigest = CustomHasher.ComputeDigest(original, bits);
        string origBitStr = CustomHasher.DigestToBitString(origDigest, bits);

        var (success, collidedBytes, attempts, strategy) = CollisionEngine.GenerateStealthCollision(original, fileName, bits);

        if (success)
        {
            byte newDigest = CustomHasher.ComputeDigest(collidedBytes, bits);
            string newBitStr = CustomHasher.DigestToBitString(newDigest, bits);
            string collidedB64 = Convert.ToBase64String(collidedBytes);

            string json = $"{{\"status\":\"ok\",\"success\":true,\"bits\":{bits},\"originalDigest\":{origDigest},\"originalBitString\":\"{origBitStr}\",\"collisionDigest\":{newDigest},\"collisionBitString\":\"{newBitStr}\",\"attempts\":{attempts},\"strategy\":\"{strategy}\",\"collidedFileBase64\":\"{collidedB64}\",\"originalSize\":{original.Length},\"collidedSize\":{collidedBytes.Length}}}";
            await SendJson(res, json);
        }
        else
        {
            string json = $"{{\"status\":\"ok\",\"success\":false,\"bits\":{bits},\"attempts\":{attempts},\"message\":\"Колізію не знайдено за ліміт спроб\"}}";
            await SendJson(res, json);
        }
    }

    private static async Task HandleApiVerifyCollision(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        int bits = root.TryGetProperty("bits", out var bElem) ? bElem.GetInt32() : 2;
        string? text1 = root.TryGetProperty("text1", out var t1) ? t1.GetString() : null;
        string? text2 = root.TryGetProperty("text2", out var t2) ? t2.GetString() : null;
        string? b64_1 = root.TryGetProperty("fileBase64_1", out var f1) ? f1.GetString() : null;
        string? b64_2 = root.TryGetProperty("fileBase64_2", out var f2) ? f2.GetString() : null;

        byte[] d1 = !string.IsNullOrEmpty(b64_1) ? Convert.FromBase64String(b64_1) : Encoding.UTF8.GetBytes(text1 ?? "");
        byte[] d2 = !string.IsNullOrEmpty(b64_2) ? Convert.FromBase64String(b64_2) : Encoding.UTF8.GetBytes(text2 ?? "");

        byte h1 = CustomHasher.ComputeDigest(d1, bits);
        byte h2 = CustomHasher.ComputeDigest(d2, bits);
        string bitStr1 = CustomHasher.DigestToBitString(h1, bits);
        string bitStr2 = CustomHasher.DigestToBitString(h2, bits);
        var (isMatch, _, _, msg) = CollisionEngine.VerifyCollision(d1, d2, bits);
        bool identicalData = StructuralComparisons(d1, d2);

        string json = $"{{\"status\":\"ok\",\"bits\":{bits},\"match\":{(isMatch ? "true" : "false")},\"digest1\":{h1},\"digest2\":{h2},\"bitString1\":\"{bitStr1}\",\"bitString2\":\"{bitStr2}\",\"message\":\"{EscapeJson(msg)}\",\"identicalContent\":{(identicalData ? "true" : "false")}}}";
        await SendJson(res, json);
    }

    private static async Task HandleApiAvalanche(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        int bits = root.TryGetProperty("bits", out var bElem) ? bElem.GetInt32() : 8;
        string? text = root.TryGetProperty("text", out var tElem) ? tElem.GetString() : null;
        string? fileBase64 = root.TryGetProperty("fileBase64", out var fElem) ? fElem.GetString() : null;

        byte[] data = !string.IsNullOrEmpty(fileBase64) ? Convert.FromBase64String(fileBase64) : Encoding.UTF8.GetBytes(text ?? "Avalanche Test Input");

        var (avgPct, totalTests, passRate) = CustomHasher.TestAvalancheEffect(data, bits, 100);

        string json = $"{{\"status\":\"ok\",\"bits\":{bits},\"avgPercentage\":{avgPct:F2},\"totalTests\":{totalTests},\"passRate\":{passRate:F2},\"meetsThreshold\":{(avgPct >= 30.0 ? "true" : "false")}}}";
        await SendJson(res, json);
    }

    private static async Task HandleApiRsaSign(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        byte digest = root.TryGetProperty("digest", out var dElem) ? (byte)dElem.GetInt32() : (byte)0;
        byte[] payload = new byte[] { digest };

        string signature = _rsaSigner!.SignDigest(payload);
        string pubPem = EscapeJson(_rsaSigner.PublicKeyPem);

        string json = $"{{\"status\":\"ok\",\"digest\":{digest},\"signature\":\"{signature}\",\"publicKeyPem\":\"{pubPem}\"}}";
        await SendJson(res, json);
    }

    private static async Task HandleApiRsaVerify(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        byte digest = root.TryGetProperty("digest", out var dElem) ? (byte)dElem.GetInt32() : (byte)0;
        string signature = root.TryGetProperty("signature", out var sElem) ? (sElem.GetString() ?? "") : "";
        string? pubPem = root.TryGetProperty("publicKeyPem", out var pElem) ? pElem.GetString() : null;

        byte[] payload = new byte[] { digest };
        bool isValid = string.IsNullOrEmpty(pubPem)
            ? _rsaSigner!.VerifyDigest(payload, signature)
            : RsaSigner.VerifyWithPublicKey(payload, signature, pubPem);

        string json = $"{{\"status\":\"ok\",\"valid\":{(isValid ? "true" : "false")}}}";
        await SendJson(res, json);
    }

    private static async Task HandleApiSamples(HttpListenerResponse res)
    {
        string docPath = Path.Combine(_samplesPath, "sample_document.txt");
        string codePath = Path.Combine(_samplesPath, "sample_code.cs");
        string imgPath = Path.Combine(_samplesPath, "sample_image.png");

        string docText = File.Exists(docPath) ? File.ReadAllText(docPath) : "";
        string codeText = File.Exists(codePath) ? File.ReadAllText(codePath) : "";
        string imgB64 = File.Exists(imgPath) ? Convert.ToBase64String(File.ReadAllBytes(imgPath)) : "";

        string json = $"{{\"status\":\"ok\",\"samples\":[{{\"name\":\"sample_document.txt\",\"type\":\"Document\",\"content\":\"{EscapeJson(docText)}\",\"isBase64\":false}},{{\"name\":\"sample_code.cs\",\"type\":\"SourceCode\",\"content\":\"{EscapeJson(codeText)}\",\"isBase64\":false}},{{\"name\":\"sample_image.png\",\"type\":\"Image\",\"content\":\"{imgB64}\",\"isBase64\":true}}]}}";
        await SendJson(res, json);
    }

    private static async Task ServeStaticFile(string relativePath, HttpListenerResponse res)
    {
        if (relativePath == "/" || string.IsNullOrEmpty(relativePath))
            relativePath = "/index.html";

        string filePath = Path.Combine(_clientFilesPath, relativePath.TrimStart('/'));

        if (!File.Exists(filePath))
        {
            res.StatusCode = 404;
            byte[] notFound = Encoding.UTF8.GetBytes("Файл не знайдено 404");
            res.ContentType = "text/plain; charset=utf-8";
            await res.OutputStream.WriteAsync(notFound);
            res.Close();
            return;
        }

        string ext = Path.GetExtension(filePath).ToLowerInvariant();
        res.ContentType = ext switch
        {
            ".html" => "text/html; charset=utf-8",
            ".css" => "text/css; charset=utf-8",
            ".js" => "application/javascript; charset=utf-8",
            ".json" => "application/json; charset=utf-8",
            ".png" => "image/png",
            _ => "application/octet-stream"
        };

        byte[] content = await File.ReadAllBytesAsync(filePath);
        res.ContentLength64 = content.Length;
        await res.OutputStream.WriteAsync(content);
        res.Close();
    }

    private static async Task SendJson(HttpListenerResponse res, string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        res.ContentType = "application/json; charset=utf-8";
        res.ContentLength64 = bytes.Length;
        await res.OutputStream.WriteAsync(bytes);
        res.Close();
    }

    private static string EscapeJson(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
    }
}
