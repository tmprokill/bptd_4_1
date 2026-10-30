using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AutoStore.Services;

public record PaymentRequest(
    string PublicKey,
    decimal Amount,
    string Currency,
    string Description,
    string OrderId,
    string Type,
    string ResultUrl,
    string ServerUrl,
    string Signature,
    string? Data = null,
    string? Mode = "sandbox"
);

public record CallbackPayload(
    string PublicKey,
    decimal Amount,
    string Currency,
    string Description,
    string OrderId,
    string Type,
    string Status,
    string TransactionId,
    string SenderPhone,
    string Signature,
    string? Data = null
);

public class SignatureVerificationResult
{
    public bool IsValid { get; set; }
    public string ExpectedSignature { get; set; } = string.Empty;
    public string ReceivedSignature { get; set; } = string.Empty;
    public string StringToSign { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class LiqPayStatusResult
{
    public bool Success { get; set; }
    public string Status { get; set; } = string.Empty;
    public string OrderId { get; set; } = string.Empty;
    public string TransactionId { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Currency { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SenderPhone { get; set; } = string.Empty;
    public string ErrCode { get; set; } = string.Empty;
    public string ErrDescription { get; set; } = string.Empty;
    public string RawJson { get; set; } = string.Empty;
}

public class LiqPayService
{
    public const string DefaultPublicKey = "sandbox_i71547430402";
    public const string DefaultPrivateKey = "sandbox_priv_key_884920402";

    private readonly object _lock = new();
    private static readonly HttpClient _httpClient = new();

    public string PublicKey { get; private set; }
    public string PrivateKey { get; private set; }
    public bool IsSandbox { get; private set; }
    public string? CustomWebhookUrl { get; private set; }

    public LiqPayService(string? publicKey = null, string? privateKey = null, bool isSandbox = true)
    {
        PublicKey = publicKey ?? DefaultPublicKey;
        PrivateKey = privateKey ?? DefaultPrivateKey;
        IsSandbox = isSandbox;
    }

    public void UpdateCredentials(string publicKey, string privateKey, bool isSandbox, string? webhookUrl = null)
    {
        lock (_lock)
        {
            if (!string.IsNullOrWhiteSpace(publicKey)) PublicKey = publicKey.Trim();
            if (!string.IsNullOrWhiteSpace(privateKey)) PrivateKey = privateKey.Trim();
            IsSandbox = isSandbox;
            CustomWebhookUrl = string.IsNullOrWhiteSpace(webhookUrl) ? null : webhookUrl.Trim();
        }
    }

    /// <summary>
    /// Розрахунок підпису форми оплати згідно з методичкою (Розділ 5.3.2, Таблиця 5.1):
    /// base64_encode(sha1(private_key + amount + currency + public_key + order_id + type + description + result_url + server_url, 1))
    /// </summary>
    public (string signature, string concatenated) CreateFormSignature(
        decimal amount,
        string currency,
        string orderId,
        string type,
        string description,
        string resultUrl,
        string serverUrl)
    {
        string amountStr = amount.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);
        string concat = $"{PrivateKey}{amountStr}{currency}{PublicKey}{orderId}{type}{description}{resultUrl}{serverUrl}";
        byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes(concat));
        string signature = Convert.ToBase64String(hash);
        return (signature, concat);
    }

    /// <summary>
    /// Розрахунок підпису зворотного виклику (callback) згідно з методичкою (Розділ 5.3.3, Таблиця 5.2):
    /// base64_encode(sha1(private_key + amount + currency + public_key + order_id + type + description + status + transaction_id + sender_phone, 1))
    /// </summary>
    public (string signature, string concatenated) CreateCallbackSignature(
        decimal amount,
        string currency,
        string orderId,
        string type,
        string description,
        string status,
        string transactionId,
        string senderPhone)
    {
        string amountStr = amount.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);
        string concat = $"{PrivateKey}{amountStr}{currency}{PublicKey}{orderId}{type}{description}{status}{transactionId}{senderPhone}";
        byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes(concat));
        string signature = Convert.ToBase64String(hash);
        return (signature, concat);
    }

    /// <summary>
    /// Офіційний протокол LiqPay v3: base64(json) та base64(sha1(private_key + data + private_key))
    /// </summary>
    public (string dataBase64, string signature) CreateV3Payment(object payload)
    {
        string json = JsonSerializer.Serialize(payload);
        string data = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
        string toSign = $"{PrivateKey}{data}{PrivateKey}";
        byte[] hash = SHA1.HashData(Encoding.UTF8.GetBytes(toSign));
        string signature = Convert.ToBase64String(hash);
        return (data, signature);
    }

    /// <summary>
    /// Верифікація підпису вхідного Callback запиту від платіжного шлюзу
    /// </summary>
    public SignatureVerificationResult VerifyCallback(CallbackPayload payload)
    {
        // 1. Якщо передано сучасний LiqPay v3 (через поле Data)
        if (!string.IsNullOrEmpty(payload.Data))
        {
            string expectedV3 = Convert.ToBase64String(SHA1.HashData(Encoding.UTF8.GetBytes($"{PrivateKey}{payload.Data}{PrivateKey}")));
            bool matchV3 = CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(payload.Signature.Trim()),
                Encoding.UTF8.GetBytes(expectedV3.Trim())
            );

            return new SignatureVerificationResult
            {
                IsValid = matchV3,
                ExpectedSignature = expectedV3,
                ReceivedSignature = payload.Signature,
                StringToSign = $"private_key + data + private_key",
                Message = matchV3 
                    ? "Підпис валідний (перевірено за офіційним стандартом LiqPay v3)" 
                    : "Помилка підпису! Виявлено спробу підробки або спотворення даних!"
            };
        }

        // 2. Стандартний підпис за формулою з методички ЛР №5
        var (expectedSig, concat) = CreateCallbackSignature(
            payload.Amount,
            payload.Currency,
            payload.OrderId,
            payload.Type,
            payload.Description,
            payload.Status,
            payload.TransactionId,
            payload.SenderPhone
        );

        bool isValid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(payload.Signature.Trim()),
            Encoding.UTF8.GetBytes(expectedSig.Trim())
        );

        return new SignatureVerificationResult
        {
            IsValid = isValid,
            ExpectedSignature = expectedSig,
            ReceivedSignature = payload.Signature,
            StringToSign = concat,
            Message = isValid
                ? "Підпис валідний (успішна криптографічна автентифікація повідомлення)"
                : "Криптографічний підпис не зійшовся! Запит відхилено (Tampering/Spoofing alert)."
        };
    }

    /// <summary>
    /// Пряме звернення до сервера LiqPay (Server-to-Server Status API)
    /// Відправляє POST https://www.liqpay.ua/api/request з action="status"
    /// </summary>
    public async Task<LiqPayStatusResult> QueryOrderStatusAsync(string orderId)
    {
        var requestObj = new
        {
            public_key = PublicKey,
            version = "3",
            action = "status",
            order_id = orderId
        };

        var (data, signature) = CreateV3Payment(requestObj);

        var formContent = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("data", data),
            new KeyValuePair<string, string>("signature", signature)
        });

        try
        {
            var response = await _httpClient.PostAsync("https://www.liqpay.ua/api/request", formContent);
            string responseBody = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(responseBody);
            var root = doc.RootElement;

            string status = root.TryGetProperty("status", out var st) ? st.GetString() ?? "" : "";
            string txId = root.TryGetProperty("transaction_id", out var tx) ? tx.ToString() : "";
            string errCode = root.TryGetProperty("err_code", out var ec) ? ec.GetString() ?? "" : "";
            string errDesc = root.TryGetProperty("err_description", out var ed) ? ed.GetString() ?? "" : "";
            string phone = root.TryGetProperty("sender_phone", out var sp) ? sp.GetString() ?? "" : "";

            decimal amount = 0;
            if (root.TryGetProperty("amount", out var am))
            {
                if (am.ValueKind == JsonValueKind.Number) amount = am.GetDecimal();
                else if (am.ValueKind == JsonValueKind.String && decimal.TryParse(am.GetString(), System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var parsed)) amount = parsed;
            }

            string currency = root.TryGetProperty("currency", out var cur) ? cur.GetString() ?? "UAH" : "UAH";
            string desc = root.TryGetProperty("description", out var ds) ? ds.GetString() ?? "" : "";

            return new LiqPayStatusResult
            {
                Success = status == "success",
                Status = status,
                OrderId = orderId,
                TransactionId = txId,
                Amount = amount,
                Currency = currency,
                Description = desc,
                SenderPhone = phone,
                ErrCode = errCode,
                ErrDescription = errDesc,
                RawJson = responseBody
            };
        }
        catch (Exception ex)
        {
            return new LiqPayStatusResult
            {
                Success = false,
                Status = "error",
                OrderId = orderId,
                ErrCode = "network_error",
                ErrDescription = ex.Message,
                RawJson = $"{{\"error\":\"{ex.Message}\"}}"
            };
        }
    }
}
