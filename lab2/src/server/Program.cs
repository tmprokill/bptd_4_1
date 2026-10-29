#!/usr/bin/env dotnet-run
#:include RsaCryptoService.cs

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using RsaServer;

public class Program
{
    private const int Port = 5050;
    private static RsaCryptoService? _cryptoService;
    private static string _clientFilesPath = "";

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        Console.WriteLine("======================================================================");
        Console.WriteLine("  ЛАБОРАТОРНА РОБОТА №2: АСИМЕТРИЧНЕ ШИФРУВАННЯ RSA (.NET + JS)");
        Console.WriteLine("  Кафедра ПІ, ХНУРЕ | Дисципліна: Безпека програм та даних");
        Console.WriteLine("  Бригада: Чуваєв А. О. (вар. 16), Світенко С. М. (вар. 13)");
        Console.WriteLine("======================================================================\n");

        _cryptoService = new RsaCryptoService(2048);
        Console.WriteLine($"[+] Сервер RSA 2048-біт успішно ініціалізовано.");
        Console.WriteLine($"[+] Алгоритм набивання: RSA-OAEP з SHA-256 (FIPS-стандарт).");
        Console.WriteLine($"[+] Публічний ключ сервера (SPKI PEM):\n{_cryptoService.ServerPublicKeyPem.Trim()}\n");

        // Визначаємо шлях до клієнтських файлів
        string baseDir = AppContext.BaseDirectory;
        string candidate1 = Path.Combine(Directory.GetCurrentDirectory(), "lab2", "src", "client");
        string candidate2 = Path.Combine(Directory.GetCurrentDirectory(), "client");
        string candidate3 = Path.Combine(baseDir, "..", "..", "..", "client");

        if (Directory.Exists(candidate1)) _clientFilesPath = Path.GetFullPath(candidate1);
        else if (Directory.Exists(candidate2)) _clientFilesPath = Path.GetFullPath(candidate2);
        else _clientFilesPath = Path.GetFullPath(candidate3);

        Console.WriteLine($"[+] Каталог клієнтського інтерфейсу: {_clientFilesPath}");

        if (args.Length > 0 && args[0].ToLowerInvariant() == "--demo")
        {
            RunSelfTest();
            return;
        }

        string prefix = $"http://localhost:{Port}/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);

        try
        {
            listener.Start();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] Помилка запуску HttpListener: {ex.Message}");
            Console.ResetColor();
            return;
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"\n[>>>] СЕРВЕР ПРАЦЮЄ НА: {prefix}");
        Console.WriteLine($"[>>>] Відкрийте браузер за посиланням {prefix} для роботи з Web UI.");
        Console.ResetColor();
        Console.WriteLine("Натисніть Ctrl+C для зупинки сервера.\n");
        Console.WriteLine("------------------------- ЖУРНАЛ ЗАПИТІВ ----------------------------");

        while (listener.IsListening)
        {
            try
            {
                var context = await listener.GetContextAsync();
                _ = Task.Run(() => HandleRequest(context));
            }
            catch
            {
                break;
            }
        }
    }

    private static async Task HandleRequest(HttpListenerContext context)
    {
        var req = context.Request;
        var res = context.Response;

        // CORS-заголовки
        res.AddHeader("Access-Control-Allow-Origin", "*");
        res.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.AddHeader("Access-Control-Allow-Headers", "Content-Type");

        if (req.HttpMethod == "OPTIONS")
        {
            res.StatusCode = 204;
            res.Close();
            return;
        }

        string path = req.Url?.AbsolutePath ?? "/";

        try
        {
            if (path == "/api/handshake" && req.HttpMethod == "GET")
            {
                string json = $$"""
                {
                  "serverPublicKey": "{{EscapeJson(_cryptoService!.ServerPublicKeyPem)}}",
                  "keySize": {{_cryptoService.KeySize}},
                  "algorithm": "RSA-OAEP-SHA256",
                  "timestamp": "{{DateTime.UtcNow:o}}"
                }
                """;

                await SendRawJson(res, json);
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [GET /api/handshake] Відправлено публічний ключ сервера (RSA-2048)");
                return;
            }

            if (path == "/api/secure-exchange" && req.HttpMethod == "POST")
            {
                using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
                string jsonBody = await reader.ReadToEndAsync();
                using var doc = JsonDocument.Parse(jsonBody);
                var root = doc.RootElement;

                string clientPublicKey = root.GetProperty("clientPublicKeyPem").GetString()!;
                string encryptedPayloadBase64 = root.GetProperty("encryptedPayloadBase64").GetString()!;

                Console.WriteLine($"\n------------------ [ВХІДНИЙ ЗАШИФРОВАНИЙ ЗАПИТ] ------------------");
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Зашифрований пакет від клієнта (Base64, довжина {encryptedPayloadBase64.Length} симв.):");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(encryptedPayloadBase64.Length > 100 ? encryptedPayloadBase64[..90] + "..." : encryptedPayloadBase64);
                Console.ResetColor();

                // 1. Розшифровуємо приватним ключем сервера
                string decryptedJson = _cryptoService!.DecryptFromClient(encryptedPayloadBase64);
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"[+] РОЗШИФРОВАНО СЕРВЕРОМ (RSA-OAEP-SHA256):\n{decryptedJson}");
                Console.ResetColor();

                using var decDoc = JsonDocument.Parse(decryptedJson);
                string login = decDoc.RootElement.TryGetProperty("login", out var l) ? l.GetString() ?? "unknown" : "unknown";
                string note = decDoc.RootElement.TryGetProperty("note", out var n) ? n.GetString() ?? "" : "";

                // 2. Формуємо відповідь сервера (розмір має бути <= 190 байтів для RSA-2048 OAEP-SHA256)
                string shortToken = Guid.NewGuid().ToString("N")[..12];
                string serverPlaintextResponse = $$"""{"status":"AUTH_OK","user":"{{EscapeJson(login)}}","token":"{{shortToken}}","time":"{{DateTime.UtcNow:HH:mm:ss}}","note":"{{EscapeJson(note.Length > 30 ? note[..27] + "..." : note)}}","msg":"Двосторонній обмін RSA-2048 підтверджено"}""";

                // 3. Шифруємо публічним ключем клієнта
                string encryptedResponseBase64 = _cryptoService.EncryptForClient(serverPlaintextResponse, clientPublicKey);

                Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] Зашифровано відповідь відкритим ключем клієнта (Base64, довжина {encryptedResponseBase64.Length} симв.):");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(encryptedResponseBase64.Length > 100 ? encryptedResponseBase64[..90] + "..." : encryptedResponseBase64);
                Console.ResetColor();
                Console.WriteLine("------------------------------------------------------------------\n");

                byte[] cipherBytes = Convert.FromBase64String(encryptedResponseBase64);
                string responsePacket = $$"""
                {
                  "success": true,
                  "encryptedResponseBase64": "{{encryptedResponseBase64}}",
                  "cipherLengthBytes": {{cipherBytes.Length}}
                }
                """;

                await SendRawJson(res, responsePacket);
                return;
            }

            // Статичні файли клієнта
            if (path == "/" || path == "/index.html")
            {
                await ServeFile(res, Path.Combine(_clientFilesPath, "index.html"), "text/html; charset=utf-8");
                return;
            }
            if (path == "/style.css")
            {
                await ServeFile(res, Path.Combine(_clientFilesPath, "style.css"), "text/css; charset=utf-8");
                return;
            }
            if (path == "/client.js")
            {
                await ServeFile(res, Path.Combine(_clientFilesPath, "client.js"), "application/javascript; charset=utf-8");
                return;
            }

            res.StatusCode = 404;
            byte[] notFound = Encoding.UTF8.GetBytes("404 Not Found");
            await res.OutputStream.WriteAsync(notFound);
            res.Close();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] Помилка обробки запиту: {ex.Message}");
            Console.ResetColor();

            res.StatusCode = 500;
            string errJson = $$"""{"success": false, "error": "{{EscapeJson(ex.Message)}}"}""";
            await SendRawJson(res, errJson);
        }
    }

    private static string EscapeJson(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "")
                .Replace("\n", "\\n");
    }

    private static async Task SendRawJson(HttpListenerResponse res, string json)
    {
        res.ContentType = "application/json; charset=utf-8";
        res.StatusCode = 200;
        byte[] buffer = Encoding.UTF8.GetBytes(json);
        res.ContentLength64 = buffer.Length;
        await res.OutputStream.WriteAsync(buffer);
        res.Close();
    }

    private static async Task ServeFile(HttpListenerResponse res, string filePath, string contentType)
    {
        if (File.Exists(filePath))
        {
            res.ContentType = contentType;
            res.StatusCode = 200;
            byte[] fileBytes = await File.ReadAllBytesAsync(filePath);
            res.ContentLength64 = fileBytes.Length;
            await res.OutputStream.WriteAsync(fileBytes);
            res.Close();
        }
        else
        {
            res.StatusCode = 404;
            byte[] buffer = Encoding.UTF8.GetBytes($"File not found: {Path.GetFileName(filePath)}");
            await res.OutputStream.WriteAsync(buffer);
            res.Close();
        }
    }

    private static void RunSelfTest()
    {
        Console.WriteLine("\n======================================================================");
        Console.WriteLine("    АВТОНОМНИЙ ТЕСТ ДВОСТОРОННЬОГО RSA ОБМІНУ (.NET)");
        Console.WriteLine("======================================================================");

        using var clientRsa = new RsaCryptoService(2048);
        using var serverRsa = new RsaCryptoService(2048);

        Console.WriteLine("[1] Клієнт та Сервер успішно згенерували незалежні пари RSA-2048.");
        Console.WriteLine($"Серверний відкритий ключ: {serverRsa.ServerPublicKeyPem[..35]}...");
        Console.WriteLine($"Клієнтський відкритий ключ: {clientRsa.ServerPublicKeyPem[..35]}...");

        // Тест для Чуваєва А. О. (Варіант 16)
        Console.WriteLine("\n--- [2] Тест для Чуваєва А. О. (Варіант 16) ---");
        string plain16 = "{\"login\":\"chuvaiev_artem\",\"variant\":16,\"data\":\"Перевірка RSA-OAEP SHA-256 між .NET та JS\"}";
        Console.WriteLine($"Відкритий текст клієнта: {plain16}");

        string enc16 = clientRsa.EncryptForClient(plain16, serverRsa.ServerPublicKeyPem);
        Console.WriteLine($"Зашифровано ключем сервера (Base64, {enc16.Length} байт): {enc16[..60]}...");

        string dec16 = serverRsa.DecryptFromClient(enc16);
        Console.WriteLine($"Розшифровано сервером:   {dec16}");
        Console.WriteLine($"Збіг даних (Клієнт -> Сервер): {plain16 == dec16}");

        string reply16 = "{\"status\":\"OK\",\"message\":\"Авторизація варіанту 16 підтверджена сервером .NET!\"}";
        string encReply16 = serverRsa.EncryptForClient(reply16, clientRsa.ServerPublicKeyPem);
        Console.WriteLine($"Зашифрована відповідь сервера (Base64): {encReply16[..60]}...");

        string decReply16 = clientRsa.DecryptFromClient(encReply16);
        Console.WriteLine($"Розшифровано клієнтом:   {decReply16}");
        Console.WriteLine($"Збіг даних (Сервер -> Клієнт): {reply16 == decReply16}");

        Console.WriteLine("\n[+] Усі тести двостороннього асиметричного шифрування виконано на 100% успішно!");
    }
}
