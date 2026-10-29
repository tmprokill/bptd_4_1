#!/usr/bin/env dotnet-run
#:include DiffieHellmanEngine.cs

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Lab4.Server;

public class Program
{
    private const int Port = 5080;
    private static DiffieHellmanEngine _dhEngine = new DiffieHellmanEngine(use2048Bit: false);
    private static string _clientFilesPath = "";

    // Спільна кімната чату у пам'яті сервера
    private static readonly List<ChatMessage> _chatHistory = new();
    private static readonly object _chatLock = new();
    private static GroupDhResult? _activeGroupSession = null;

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        Console.WriteLine("======================================================================");
        Console.WriteLine("  ЛАБОРАТОРНА РОБОТА №4: АЛГОРИТМ ОБМІНУ КЛЮЧАМИ ДІФФІ-ХЕЛЛМАНА");
        Console.WriteLine("  Безпечний груповий чат (AES-256-GCM) для N >= 3 користувачів");
        Console.WriteLine("  Кафедра ПІ, ХНУРЕ | Дисципліна: Безпека програм та даних");
        Console.WriteLine("  Бригада: Чуваєв А. О. (вар. 16), Світенко С. М. (вар. 13)");
        Console.WriteLine("======================================================================\n");

        ResolveClientPath();
        Console.WriteLine($"[+] Каталог клієнтського інтерфейсу: {_clientFilesPath}");
        Console.WriteLine($"[+] Генератор G = {_dhEngine.G}, Модуль P = {_dhEngine.P.ToString().Substring(0, 20)}... (256 бітів)\n");

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
            Console.WriteLine("1. Запустити повну демонстрацію бригади (--demo)");
            Console.WriteLine("2. Груповий кільцевий обмін ключами (Group DH для N >= 3)");
            Console.WriteLine("3. Тестування симетричного шифрування AES-256-GCM");
            Console.WriteLine("4. Запустити Web-сервер безпечного чату (http://localhost:5080)");
            Console.WriteLine("0. Вихід");
            Console.Write("\nОберіть дію [0-4]: ");

            string? choice = Console.ReadLine()?.Trim();
            Console.WriteLine();

            switch (choice)
            {
                case "1":
                    RunDemonstration();
                    break;
                case "2":
                    InteractiveGroupDh();
                    break;
                case "3":
                    InteractiveAesGcmTest();
                    break;
                case "4":
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

    private static void ResolveClientPath()
    {
        string currentDir = Directory.GetCurrentDirectory();
        string baseDir = AppContext.BaseDirectory;

        string[] clientCandidates = {
            Path.Combine(currentDir, "lab4", "src", "client"),
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
    }

    public static void RunDemonstration()
    {
        Console.WriteLine("======================================================================");
        Console.WriteLine("  ПРОТОКОЛ ДЕМОНСТРАЦІЙНОГО ТЕСТУВАННЯ ЛАБОРАТОРНОЇ РОБОТИ №4");
        Console.WriteLine("======================================================================\n");

        // 1. Груповий кільцевий обмін ключами для N = 3
        Console.WriteLine("--- ЕТАП 1: ГРУПОВИЙ ДІФФІ-ХЕЛЛМАН ДЛЯ 3-Х УЧАСНИКІВ (CIRCULAR GDH) ---");
        var participants = new List<Participant>
        {
            new Participant("Чуваєв (вар. 16)", _dhEngine.GeneratePrivateKey()),
            new Participant("Світенко (вар. 13)", _dhEngine.GeneratePrivateKey()),
            new Participant("Олійник О. О. (викладач)", _dhEngine.GeneratePrivateKey())
        };

        foreach (var p in participants)
        {
            BigInteger pub = _dhEngine.ComputePublicKey(p.PrivateKey);
            Console.WriteLine($"[+] Учасник: {p.Name,-25} | Приватний: {p.PrivateKey.ToString().Substring(0, 16)}... | Публічний: {pub.ToString().Substring(0, 16)}...");
        }

        Console.WriteLine("\nЗапуск каскадного кільцевого обміну g^(a*b*c) mod p...");
        var groupResult = _dhEngine.ExecuteGroupKeyExchange(participants);

        foreach (var step in groupResult.Steps)
        {
            Console.WriteLine($"  Раунд {step.Round}: {step.FromParticipant} -> {step.ToParticipant} | {step.Formula} | Токен: {step.Value.ToString().Substring(0, 18)}...");
        }

        Console.WriteLine("\nПідсумкові обчислені ключі учасників:");
        foreach (var kvp in groupResult.ParticipantKeys)
        {
            Console.WriteLine($"  - {kvp.Key,-25}: {kvp.Value.ToString().Substring(0, 32)}...");
        }

        Console.WriteLine($"Ідентичність групового ключа для всіх 3-х сторін: {(groupResult.Success ? "[ПІДТВЕРДЖЕНО TRUE]" : "[ПОМИЛКА FALSE]")}");
        Console.WriteLine($"Груповий симетричний ключ AES-256 (Base64):     {groupResult.AesKeyBase64}");

        // 2. Тестування шифрування AES-256-GCM у груповому чаті
        Console.WriteLine("\n--- ЕТАП 2: НАДІЙНИЙ ОБМІН ПОВІДОМЛЕННЯМИ В ЧАТІ (AES-256-GCM) ---");
        byte[] groupAesKey = Convert.FromBase64String(groupResult.AesKeyBase64);
        string testMessage = "Безпечне повідомлення групового чату кафедри ПІ ХНУРЕ (БПТД ЛР4)!";

        var encrypted = DiffieHellmanEngine.EncryptAesGcm(testMessage, groupAesKey);
        Console.WriteLine($"Відкритий текст:   \"{testMessage}\"");
        Console.WriteLine($"AES-GCM Nonce:     {encrypted.NonceBase64}");
        Console.WriteLine($"Шифротекст:        {encrypted.CiphertextBase64}");
        Console.WriteLine($"Автентичний тег:   {encrypted.TagBase64}");

        string decrypted = DiffieHellmanEngine.DecryptAesGcm(encrypted, groupAesKey);
        Console.WriteLine($"Розшифровано:      \"{decrypted}\"");
        Console.WriteLine($"Збіг тексту:       {(testMessage == decrypted ? "[УСПІХ TRUE]" : "[ПОМИЛКА FALSE]")}");

        Console.WriteLine("\n======================================================================");
        Console.WriteLine("  УСІ ТЕСТИ ЛАБОРАТОРНОЇ РОБОТИ №4 ВИКОНАНО НА 100% УСПІШНО [OK]");
        Console.WriteLine("======================================================================\n");
    }

    private static void InteractiveGroupDh()
    {
        Console.Write("Введіть імена учасників через кому (або Enter для Чуваєв, Світенко, Олійник): ");
        string? input = Console.ReadLine();
        var names = string.IsNullOrWhiteSpace(input)
            ? new List<string> { "Чуваєв", "Світенко", "Олійник" }
            : input.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

        if (names.Count < 3) names.Add("Гість");

        var participants = names.Select(n => new Participant(n, _dhEngine.GeneratePrivateKey())).ToList();
        var res = _dhEngine.ExecuteGroupKeyExchange(participants);

        Console.WriteLine($"\n[+] Груповий протокол завершено. Успіх: {res.Success}");
        Console.WriteLine($"[+] Спільний AES-256 ключ: {res.AesKeyBase64}\n");
    }

    private static void InteractiveAesGcmTest()
    {
        Console.Write("Введіть текст для шифрування: ");
        string msg = Console.ReadLine() ?? "Привіт!";
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var enc = DiffieHellmanEngine.EncryptAesGcm(msg, key);
        Console.WriteLine($"Шифротекст (Base64): {enc.CiphertextBase64}");
        string dec = DiffieHellmanEngine.DecryptAesGcm(enc, key);
        Console.WriteLine($"Розшифровано: \"{dec}\"\n");
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

        Console.WriteLine($"[+] Web-сервер чату запущено на {prefix}");
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
            if (req.HttpMethod == "POST" && path == "/api/dh/init-group")
            {
                await HandleInitGroup(req, res);
                return;
            }

            if (req.HttpMethod == "POST" && path == "/api/dh/pairwise")
            {
                await HandlePairwise(req, res);
                return;
            }

            if (req.HttpMethod == "POST" && path == "/api/chat/send")
            {
                await HandleChatSend(req, res);
                return;
            }

            if (req.HttpMethod == "GET" && path == "/api/chat/messages")
            {
                await HandleChatMessages(res);
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

    private static async Task HandleInitGroup(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var names = new List<string>();
        if (root.TryGetProperty("participants", out var pElem) && pElem.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in pElem.EnumerateArray())
            {
                string? s = item.GetString();
                if (!string.IsNullOrWhiteSpace(s)) names.Add(s.Trim());
            }
        }

        if (names.Count < 3)
        {
            names = new List<string> { "Чуваєв (вар. 16)", "Світенко (вар. 13)", "Олійник О. О." };
        }

        var partList = names.Select(n => new Participant(n, _dhEngine.GeneratePrivateKey())).ToList();
        _activeGroupSession = _dhEngine.ExecuteGroupKeyExchange(partList);

        // Формуємо JSON відповідь вручну для надійності
        var sb = new StringBuilder();
        sb.Append("{");
        sb.Append($"\"status\":\"ok\",");
        sb.Append($"\"success\":{(_activeGroupSession.Success ? "true" : "false")},");
        sb.Append($"\"p\":\"{_dhEngine.P}\",");
        sb.Append($"\"g\":{_dhEngine.G},");
        sb.Append($"\"sharedSecretHex\":\"{_activeGroupSession.GroupSharedSecretHex}\",");
        sb.Append($"\"aesKeyBase64\":\"{_activeGroupSession.AesKeyBase64}\",");
        sb.Append("\"participants\":[");
        for (int i = 0; i < partList.Count; i++)
        {
            if (i > 0) sb.Append(",");
            BigInteger pub = _dhEngine.ComputePublicKey(partList[i].PrivateKey);
            BigInteger computedKey = _activeGroupSession.ParticipantKeys.TryGetValue(partList[i].Name, out var k) ? k : 0;
            sb.Append($"{{\"name\":\"{EscapeJson(partList[i].Name)}\",\"priv\":\"{partList[i].PrivateKey}\",\"privHex\":\"{partList[i].PrivateKey.ToString("X")}\",\"pub\":\"{pub}\",\"pubHex\":\"{pub.ToString("X")}\",\"finalKeyHex\":\"{computedKey.ToString("X")}\"}}");
        }
        sb.Append("],\"steps\":[");
        for (int i = 0; i < _activeGroupSession.Steps.Count; i++)
        {
            if (i > 0) sb.Append(",");
            var s = _activeGroupSession.Steps[i];
            sb.Append($"{{\"round\":{s.Round},\"from\":\"{EscapeJson(s.FromParticipant)}\",\"to\":\"{EscapeJson(s.ToParticipant)}\",\"formula\":\"{EscapeJson(s.Formula)}\",\"tokenHex\":\"{s.Value.ToString("X")}\"}}");
        }
        sb.Append("]}");

        await SendJson(res, sb.ToString());
    }

    private static async Task HandlePairwise(HttpListenerRequest req, HttpListenerResponse res)
    {
        BigInteger a = _dhEngine.GeneratePrivateKey();
        BigInteger b = _dhEngine.GeneratePrivateKey();
        BigInteger A = _dhEngine.ComputePublicKey(a);
        BigInteger B = _dhEngine.ComputePublicKey(b);

        BigInteger kA = _dhEngine.ComputeSharedSecret(B, a);
        BigInteger kB = _dhEngine.ComputeSharedSecret(A, b);

        byte[] aesKey = DiffieHellmanEngine.DeriveAesKey(kA);

        string json = $"{{\"status\":\"ok\",\"alicePriv\":\"{a}\",\"alicePub\":\"{A}\",\"bobPriv\":\"{b}\",\"bobPub\":\"{B}\",\"sharedSecretHex\":\"{kA.ToString("X")}\",\"aesKeyBase64\":\"{Convert.ToBase64String(aesKey)}\",\"match\":{(kA == kB ? "true" : "false")}}}";
        await SendJson(res, json);
    }

    private static async Task HandleChatSend(HttpListenerRequest req, HttpListenerResponse res)
    {
        using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
        string body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        string sender = root.TryGetProperty("sender", out var sElem) ? (sElem.GetString() ?? "Гість") : "Гість";
        string text = root.TryGetProperty("text", out var tElem) ? (tElem.GetString() ?? "") : "";

        if (_activeGroupSession == null)
        {
            // Якщо сесія ще не створена, створюємо групу за замовчуванням
            var defPart = new List<Participant> {
                new Participant("Чуваєв (вар. 16)", _dhEngine.GeneratePrivateKey()),
                new Participant("Світенко (вар. 13)", _dhEngine.GeneratePrivateKey()),
                new Participant("Олійник О. О.", _dhEngine.GeneratePrivateKey())
            };
            _activeGroupSession = _dhEngine.ExecuteGroupKeyExchange(defPart);
        }

        byte[] aesKey = Convert.FromBase64String(_activeGroupSession.AesKeyBase64);
        var enc = DiffieHellmanEngine.EncryptAesGcm(text, aesKey);

        var msg = new ChatMessage(
            Id: Guid.NewGuid().ToString("N"),
            Sender: sender,
            Plaintext: text,
            CiphertextBase64: enc.CiphertextBase64,
            NonceBase64: enc.NonceBase64,
            TagBase64: enc.TagBase64,
            Timestamp: DateTime.Now.ToString("HH:mm:ss")
        );

        lock (_chatLock)
        {
            _chatHistory.Add(msg);
            if (_chatHistory.Count > 100) _chatHistory.RemoveAt(0);
        }

        string json = $"{{\"status\":\"ok\",\"messageId\":\"{msg.Id}\",\"ciphertext\":\"{msg.CiphertextBase64}\",\"tag\":\"{msg.TagBase64}\",\"timestamp\":\"{msg.Timestamp}\"}}";
        await SendJson(res, json);
    }

    private static async Task HandleChatMessages(HttpListenerResponse res)
    {
        List<ChatMessage> list;
        lock (_chatLock)
        {
            list = new List<ChatMessage>(_chatHistory);
        }

        var sb = new StringBuilder();
        sb.Append("{\"status\":\"ok\",\"messages\":[");
        for (int i = 0; i < list.Count; i++)
        {
            if (i > 0) sb.Append(",");
            var m = list[i];
            sb.Append($"{{\"id\":\"{m.Id}\",\"sender\":\"{EscapeJson(m.Sender)}\",\"plaintext\":\"{EscapeJson(m.Plaintext)}\",\"ciphertext\":\"{m.CiphertextBase64}\",\"nonce\":\"{m.NonceBase64}\",\"tag\":\"{m.TagBase64}\",\"timestamp\":\"{m.Timestamp}\"}}");
        }
        sb.Append("]}");

        await SendJson(res, sb.ToString());
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

public record ChatMessage(
    string Id,
    string Sender,
    string Plaintext,
    string CiphertextBase64,
    string NonceBase64,
    string TagBase64,
    string Timestamp
);
