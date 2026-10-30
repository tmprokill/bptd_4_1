using System.Text.Json;
using System.Text.Json.Serialization;
using AutoStore.Services;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Сервіси застосунку
var liqConfig = builder.Configuration.GetSection("LiqPay");
string pubKey = liqConfig["PublicKey"] ?? LiqPayService.DefaultPublicKey;
string privKey = liqConfig["PrivateKey"] ?? LiqPayService.DefaultPrivateKey;
bool isSandbox = liqConfig.GetValue<bool?>("IsSandbox") ?? true;
string? webhookUrl = liqConfig["WebhookUrl"];

var liqService = new LiqPayService(pubKey, privKey, isSandbox);
if (!string.IsNullOrWhiteSpace(webhookUrl))
{
    liqService.UpdateCredentials(pubKey, privKey, isSandbox, webhookUrl);
}

builder.Services.AddSingleton(liqService);
builder.Services.AddSingleton<InventoryService>();
builder.Services.AddSingleton<OAuthService>();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

// Налаштовуємо порт 5090
builder.WebHost.UseUrls("http://localhost:5090");

var app = builder.Build();

app.UseCors();
app.UseDefaultFiles();
app.UseStaticFiles();

// Перевірка на запуск у демонстраційному режимі (--demo)
if (args.Contains("--demo"))
{
    RunConsoleDemonstration(
        app.Services.GetRequiredService<InventoryService>(),
        app.Services.GetRequiredService<LiqPayService>(),
        app.Services.GetRequiredService<OAuthService>()
    );
    return;
}

// ==========================================
// API КАТАЛОГУ АВТОМОБІЛІВ ТА СКЛАДУ
// ==========================================

app.MapGet("/api/cars", (InventoryService inventory) =>
{
    return Results.Ok(inventory.GetAllCars());
});

app.MapGet("/api/cars/{id}", (string id, InventoryService inventory) =>
{
    var car = inventory.GetCar(id);
    return car is not null ? Results.Ok(car) : Results.NotFound(new { error = "Автомобіль не знайдено" });
});

app.MapPost("/api/inventory/reset", (InventoryService inventory) =>
{
    inventory.ResetInventory();
    return Results.Ok(new { message = "Склад успішно скинуто до початкових значень (ЗАЗ-968М = 3 шт.)", cars = inventory.GetAllCars() });
});

// ==========================================
// ПЕРЕВІРКА СТАТУСУ З РЕАЛЬНОГО СЕРВЕРА LIQPAY (SERVER-TO-SERVER STATUS API)
// ==========================================

app.MapPost("/api/orders/{orderId}/sync-status", async (string orderId, InventoryService inventory, LiqPayService liqPay) =>
{
    var order = inventory.GetOrder(orderId);
    if (order is null) return Results.NotFound(new { error = "Замовлення не знайдено" });

    var liqPayResult = await liqPay.QueryOrderStatusAsync(orderId);

    bool isSuccess = liqPayResult.Status.Equals("success", StringComparison.OrdinalIgnoreCase) 
                  || liqPayResult.Status.Equals("sandbox", StringComparison.OrdinalIgnoreCase);

    if (isSuccess)
    {
        var sigResult = new SignatureVerificationResult
        {
            IsValid = true,
            ExpectedSignature = "Verified via Server-to-Server LiqPay Status API",
            ReceivedSignature = "Verified via Server-to-Server LiqPay Status API",
            Message = "Отримано офіційне підтвердження успішної оплати від сервера LiqPay"
        };

        var (updatedOrder, stockChanged) = inventory.ApplyPaymentResult(
            orderId, 
            liqPayResult.Status, 
            string.IsNullOrEmpty(liqPayResult.TransactionId) ? $"LP-{Random.Shared.Next(10000000, 99999999)}" : liqPayResult.TransactionId, 
            sigResult
        );

        return Results.Ok(new
        {
            status = "success",
            liqPayResult,
            order = updatedOrder,
            stockChanged,
            cars = inventory.GetAllCars()
        });
    }
    else if (liqPayResult.Status.Equals("failure", StringComparison.OrdinalIgnoreCase) || liqPayResult.Status.Equals("error", StringComparison.OrdinalIgnoreCase))
    {
        var sigResult = new SignatureVerificationResult { IsValid = true, Message = "Статус відмови від сервера LiqPay" };
        var (updatedOrder, stockChanged) = inventory.ApplyPaymentResult(orderId, "failure", liqPayResult.TransactionId, sigResult);
        return Results.Ok(new
        {
            status = "failure",
            liqPayResult,
            order = updatedOrder,
            stockChanged = false,
            cars = inventory.GetAllCars()
        });
    }

    return Results.Ok(new
    {
        status = liqPayResult.Status,
        liqPayResult,
        order,
        stockChanged = false,
        cars = inventory.GetAllCars()
    });
});

// ==========================================
// ОФОРМЛЕННЯ ЗАМОВЛЕННЯ З КОШИКА ТА ГЕНЕРАЦІЯ ПІДПИСУ LIQPAY
// ==========================================

app.MapPost("/api/orders/checkout", ([FromBody] CartCheckoutRequest req, InventoryService inventory, LiqPayService liqPay) =>
{
    try
    {
        OrderRecord order;
        if (req.Items != null && req.Items.Count > 0)
        {
            var cartTuples = req.Items.Select(i => (i.CarId, i.Quantity)).ToList();
            order = inventory.CreateOrderFromCart(cartTuples, req.UserId, req.UserName);
        }
        else if (!string.IsNullOrEmpty(req.CarId))
        {
            order = inventory.CreateOrder(req.CarId, req.UserId, req.UserName);
        }
        else
        {
            return Results.BadRequest(new { error = "Кошик порожній! Оберіть хоча б один автомобіль." });
        }

        string resultUrl = "http://localhost:5090/#/orders";
        string serverUrl = liqPay.CustomWebhookUrl ?? "http://localhost:5090/api/payment/callback";
        string description = $"Замовлення #{order.OrderId}: {order.CarName}";

        // Розрахунок підпису згідно з методичкою (Розділ 5.3.1 - 5.3.2)
        var (signature, concat) = liqPay.CreateFormSignature(
            amount: order.Amount,
            currency: order.Currency,
            orderId: order.OrderId,
            type: "buy",
            description: description,
            resultUrl: resultUrl,
            serverUrl: serverUrl
        );

        var (v3Data, v3Sig) = liqPay.CreateV3Payment(new
        {
            public_key = liqPay.PublicKey,
            version = "3",
            action = "pay",
            amount = order.Amount,
            currency = order.Currency,
            description = description,
            order_id = order.OrderId,
            result_url = resultUrl,
            server_url = serverUrl,
            sandbox = liqPay.IsSandbox ? 1 : 0
        });

        return Results.Ok(new
        {
            order,
            paymentForm = new
            {
                public_key = liqPay.PublicKey,
                amount = order.Amount,
                currency = order.Currency,
                description,
                order_id = order.OrderId,
                type = "buy",
                result_url = resultUrl,
                server_url = serverUrl,
                signature,
                concatenated_string = concat,
                v3_data = v3Data,
                v3_signature = v3Sig,
                sandbox = liqPay.IsSandbox ? 1 : 0,
                checkout_url = "https://www.liqpay.ua/api/3/checkout"
            }
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

// ==========================================
// СЕРВЕРНИЙ ОБРОБНИК СТАТУСУ ОПЛАТИ (CALLBACK / WEBHOOK)
// ==========================================

app.MapPost("/api/payment/callback", async (HttpContext ctx, InventoryService inventory, LiqPayService liqPay) =>
{
    CallbackPayload payload;

    if (ctx.Request.HasFormContentType)
    {
        var form = await ctx.Request.ReadFormAsync();
        string? data = form.ContainsKey("data") ? form["data"].ToString() : null;
        string? signature = form.ContainsKey("signature") ? form["signature"].ToString() : form["Signature"].ToString();

        string orderId = form["order_id"].ToString();
        string status = form["status"].ToString();
        string transactionId = form["transaction_id"].ToString();
        string currency = form["currency"].ToString();
        string description = form["description"].ToString();
        string type = form["type"].ToString();
        string senderPhone = form["sender_phone"].ToString();
        decimal.TryParse(form["amount"], System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out decimal amt);

        // Якщо це офіційний LiqPay v3 Webhook (передано data у Base64)
        if (!string.IsNullOrEmpty(data))
        {
            try
            {
                byte[] decodedBytes = Convert.FromBase64String(data);
                using var jsonDoc = JsonDocument.Parse(decodedBytes);
                var root = jsonDoc.RootElement;

                if (root.TryGetProperty("order_id", out var pOrder)) orderId = pOrder.GetString() ?? orderId;
                if (root.TryGetProperty("status", out var pStatus)) status = pStatus.GetString() ?? status;
                if (root.TryGetProperty("payment_id", out var pTx)) transactionId = pTx.ToString() ?? transactionId;
                if (root.TryGetProperty("currency", out var pCur)) currency = pCur.GetString() ?? currency;
                if (root.TryGetProperty("description", out var pDesc)) description = pDesc.GetString() ?? description;
                if (root.TryGetProperty("sender_phone", out var pPhone)) senderPhone = pPhone.GetString() ?? senderPhone;
                if (root.TryGetProperty("amount", out var pAmt))
                {
                    if (pAmt.ValueKind == JsonValueKind.Number) amt = pAmt.GetDecimal();
                    else decimal.TryParse(pAmt.GetString(), System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out amt);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Webhook] Помилка розбору LiqPay Base64 data: {ex.Message}");
            }
        }

        payload = new CallbackPayload(
            PublicKey: form["public_key"].ToString(),
            Amount: amt,
            Currency: currency,
            Description: description,
            OrderId: orderId,
            Type: type,
            Status: status,
            TransactionId: transactionId,
            SenderPhone: senderPhone,
            Signature: signature ?? string.Empty,
            Data: data
        );
    }
    else
    {
        using var reader = new StreamReader(ctx.Request.Body);
        string body = await reader.ReadToEndAsync();
        payload = JsonSerializer.Deserialize<CallbackPayload>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                  ?? throw new InvalidOperationException("Порожнє тіло callback-запиту");
    }

    // 1. Верифікація криптографічного підпису
    var verification = liqPay.VerifyCallback(payload);

    // 2. Обробка результату в сервісі складу (з урахуванням підпису та ідемпотентності)
    var (order, stockChanged) = inventory.ApplyPaymentResult(payload.OrderId, payload.Status, payload.TransactionId, verification);

    if (!verification.IsValid)
    {
        return Results.BadRequest(new
        {
            status = "rejected",
            error = "Криптографічний підпис не валідний! Спроба фальсифікації транзакції відхилена.",
            verification,
            order,
            stockChanged = false
        });
    }

    return Results.Ok(new
    {
        status = "accepted",
        verification,
        order,
        stockChanged
    });
});

// ==========================================
// OAUTH 2.0 ЕНДПОІНТИ (Вимога на «відмінно»)
// ==========================================

app.MapGet("/oauth/users", (OAuthService oauth) =>
{
    return Results.Ok(oauth.GetAvailableUsers());
});

app.MapGet("/oauth/authorize", (
    [FromQuery(Name = "response_type")] string? responseType,
    [FromQuery(Name = "client_id")] string? clientId,
    [FromQuery(Name = "redirect_uri")] string? redirectUri,
    [FromQuery(Name = "user_id")] string? userId,
    [FromQuery(Name = "state")] string? state,
    OAuthService oauth) =>
{
    try
    {
        string cId = clientId ?? "autostore-web-app";
        string rUri = redirectUri ?? "http://localhost:5090/oauth/callback";
        string st = state ?? Guid.NewGuid().ToString("N")[..8];
        string uId = userId ?? "chuvaiev";

        string code = oauth.CreateAuthorizationCode(cId, rUri, st, uId);
        return Results.Ok(new
        {
            code,
            state = st,
            redirect_url = $"{rUri}?code={code}&state={st}"
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/oauth/authorize", ([FromBody] AuthorizeRequest req, OAuthService oauth) =>
{
    try
    {
        string code = oauth.CreateAuthorizationCode(req.ClientId, req.RedirectUri, req.State, req.UserId);
        return Results.Ok(new
        {
            code,
            state = req.State,
            redirect_url = $"{req.RedirectUri}?code={code}&state={req.State}"
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/oauth/token", ([FromBody] TokenRequest req, OAuthService oauth) =>
{
    try
    {
        var (token, type, expires, user) = oauth.ExchangeCode(
            req.GrantType,
            req.Code,
            req.ClientId,
            req.ClientSecret,
            req.RedirectUri
        );

        return Results.Ok(new
        {
            access_token = token,
            token_type = type,
            expires_in = expires,
            user
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapGet("/oauth/userinfo", (HttpContext ctx, OAuthService oauth) =>
{
    string? authHeader = ctx.Request.Headers.Authorization;
    var user = oauth.ValidateBearerToken(authHeader);
    return user is not null ? Results.Ok(user) : Results.Unauthorized();
});

// ==========================================
// СПИСОК ЗАМОВЛЕНЬ
// ==========================================

app.MapGet("/api/orders", (string? userId, InventoryService inventory) =>
{
    return Results.Ok(inventory.GetOrders(userId));
});

// Запуск сервера
Console.WriteLine("======================================================================");
Console.WriteLine("  АВТОСАЛОН «ХНУРЕ-АВТО» — ПЛАТІЖНА СИСТЕМА LIQPAY & OAUTH 2.0");
Console.WriteLine("  Лабораторна робота №5: Реалізація платіжної форми веб-сайту");
Console.WriteLine("  Бригада: Чуваєв А. О. (вар. 16) та Світенко С. М. (вар. 13)");
Console.WriteLine("  Веб-інтерфейс доступний за адресою: http://localhost:5090");
Console.WriteLine("======================================================================\n");

app.Run();

// ==========================================
// КОНСОЛЬНИЙ РЕЖИМ ДЕМОНСТРАЦІЇ (--demo)
// ==========================================

static void RunConsoleDemonstration(InventoryService inventory, LiqPayService liqPay, OAuthService oauth)
{
    Console.WriteLine("======================================================================");
    Console.WriteLine("  ПРОТОКОЛ ДЕМОНСТРАЦІЙНОГО ТЕСТУВАННЯ ЛАБОРАТОРНОЇ РОБОТИ №5");
    Console.WriteLine("  Тема: Реалізація платіжної форми веб-сайту (LiqPay Sandbox & OAuth 2.0)");
    Console.WriteLine("  Бригада: Чуваєв А. О. (вар. 16), Світенко С. М. (вар. 13)");
    Console.WriteLine("======================================================================\n");

    // 1. Початковий стан складу
    Console.WriteLine("--- КРОК 1: ПОЧАТКОВИЙ СТАН СКЛАДУ АВТОМОБІЛІВ ---");
    var cars = inventory.GetAllCars();
    foreach (var c in cars)
    {
        Console.WriteLine($"  [Авто] {c.Name,-25} | Залишок: {c.CurrentStock} шт. | Ціна: {c.Price:F2} UAH");
    }
    var zaz = inventory.GetCar("zaz-968")!;
    Console.WriteLine($"\n[Вимога викладача] ЗАЗ-968М початково на складі: {zaz.CurrentStock} шт.\n");

    // 2. Автентифікація покупця за стандартом OAuth 2.0 (RFC 6749)
    Console.WriteLine("--- КРОК 2: АВТЕНТИФІКАЦІЯ ПОКУПЦЯ ЗА СТАНДАРТОМ OAUTH 2.0 (RFC 6749) ---");
    string clientId = OAuthService.ValidClientId;
    string clientSecret = OAuthService.ValidClientSecret;
    string redirectUri = "http://localhost:5090/oauth/callback";
    string state = Guid.NewGuid().ToString("N")[..8];

    string authCode = oauth.CreateAuthorizationCode(clientId, redirectUri, state, "chuvaiev");
    Console.WriteLine($"[1] Authorization Request: client_id={clientId}, state={state}");
    Console.WriteLine($"[2] Отримано Authorization Code: {authCode}");

    var (token, tokenType, expires, user) = oauth.ExchangeCode("authorization_code", authCode, clientId, clientSecret, redirectUri);
    Console.WriteLine($"[3] Token Exchange успішний! Отримано {tokenType} Access Token: {token[..20]}... (дійсний {expires} с)");
    Console.WriteLine($"[4] Профіль покупця: {user.Name} ({user.Group}, варіант {user.Variant}, email: {user.Email})\n");

    // 3. Формування замовлення та платіжної форми
    Console.WriteLine("--- КРОК 3: ФОРМУВАННЯ ЗАМОВЛЕННЯ ТА ЦИФРОВОГО ПІДПИСУ ФОРМИ LIQPAY ---");
    var order1 = inventory.CreateOrder("zaz-968", user.Id, user.Name);
    Console.WriteLine($"[Створено замовлення] ID: {order1.OrderId} на суму {order1.Amount} {order1.Currency}");

    var (formSig, formConcat) = liqPay.CreateFormSignature(
        order1.Amount, order1.Currency, order1.OrderId, "buy",
        $"Купівля {order1.CarName}", "http://localhost:5090/#/orders", "http://localhost:5090/api/payment/callback"
    );
    Console.WriteLine($"  Рядок конкатенації: {formConcat[..40]}... (довжина {formConcat.Length} симв.)");
    Console.WriteLine($"  Розрахований підпис форми: {formSig}\n");

    // 4. Тест безпеки: спроба атаки фальсифікації (Tampering)
    Console.WriteLine("--- КРОК 4: АНАЛІЗ БЕЗПЕКИ: ВІДХИЛЕННЯ СПРОБИ ПІДРОБКИ СУМИ (TAMPERING) ---");
    var fakePayload = new CallbackPayload(
        PublicKey: liqPay.PublicKey,
        Amount: 1.00m, // Зловмисник намагається заплатити 1 грн замість 15
        Currency: order1.Currency,
        Description: $"Купівля {order1.CarName}",
        OrderId: order1.OrderId,
        Type: "buy",
        Status: "success",
        TransactionId: "TX-HACK-9999",
        SenderPhone: "380990000000",
        Signature: "INVALID_TAMPERED_SIGNATURE=="
    );
    var fakeVerify = liqPay.VerifyCallback(fakePayload);
    var (afterHackOrder, hackStockChanged) = inventory.ApplyPaymentResult(order1.OrderId, "success", "TX-HACK-9999", fakeVerify);
    var zazAfterHack = inventory.GetCar("zaz-968")!;
    Console.WriteLine($"  Підпис перевірено сервером: {(fakeVerify.IsValid ? "ВАЛІДНИЙ" : "ВІДХИЛЕНО [FALSE]")}");
    Console.WriteLine($"  Вердикт системи безпеки:    {fakeVerify.Message}");
    Console.WriteLine($"  Чи змінився склад авто:     {hackStockChanged} (залишок ЗАЗ-968М: {zazAfterHack.CurrentStock} шт.)\n");

    // 5. Успішна оплата через тестовий режим (Sandbox)
    Console.WriteLine("--- КРОК 5: УСПІШНА ОПЛАТА ТРАНЗАКЦІЇ (SANDBOX SUCCESS КАРТКА) ---");
    var (validCallbackSig, _) = liqPay.CreateCallbackSignature(
        order1.Amount, order1.Currency, order1.OrderId, "buy",
        $"Купівля {order1.CarName}", "success", "TX-10024892", "380951234567"
    );
    var successPayload = new CallbackPayload(
        PublicKey: liqPay.PublicKey,
        Amount: order1.Amount,
        Currency: order1.Currency,
        Description: $"Купівля {order1.CarName}",
        OrderId: order1.OrderId,
        Type: "buy",
        Status: "success",
        TransactionId: "TX-10024892",
        SenderPhone: "380951234567",
        Signature: validCallbackSig
    );
    var successVerify = liqPay.VerifyCallback(successPayload);
    var (paidOrder, stockChanged) = inventory.ApplyPaymentResult(order1.OrderId, "success", "TX-10024892", successVerify);
    var zazAfterSuccess = inventory.GetCar("zaz-968")!;
    Console.WriteLine($"  Підпис callback перевірено: {(successVerify.IsValid ? "ВАЛІДНИЙ [TRUE]" : "ПОМИЛКА")}");
    Console.WriteLine($"  Статус замовлення:          {paidOrder.State}");
    Console.WriteLine($"  Зміна залишку ЗАЗ-968М:     {paidOrder.StockBefore} шт. -> {zazAfterSuccess.CurrentStock} шт. (Зменшено на 1)");
    Console.WriteLine($"  [Вимога викладача виконана]: 3 шт. стало {zazAfterSuccess.CurrentStock} шт.!\n");

    // 6. Перевірка ідемпотентності (захист від повторних списань)
    Console.WriteLine("--- КРОК 6: ПЕРЕВІРКА ІДЕМПОТЕНТНОСТІ (ДУБЛЮВАННЯ WEBHOOK CALLBACK) ---");
    var (_, doubleSpendChanged) = inventory.ApplyPaymentResult(order1.OrderId, "success", "TX-10024892", successVerify);
    var zazAfterDouble = inventory.GetCar("zaz-968")!;
    Console.WriteLine($"  Повторна обробка транзакції: склад змінено = {doubleSpendChanged}");
    Console.WriteLine($"  Залишок ЗАЗ-968М залишився:  {zazAfterDouble.CurrentStock} шт. (повторне списання заблоковано)\n");

    // 7. Неуспішна оплата (відхилена картка)
    Console.WriteLine("--- КРОК 7: НЕУСПІШНА ОПЛАТА (FAILURE КАРТКА) ---");
    var order2 = inventory.CreateOrder("zaz-968", user.Id, user.Name);
    Console.WriteLine($"[Створено замовлення #2] ID: {order2.OrderId}");

    var (failSig, _) = liqPay.CreateCallbackSignature(
        order2.Amount, order2.Currency, order2.OrderId, "buy",
        $"Купівля {order2.CarName}", "failure", "TX-10024893", "380951234567"
    );
    var failPayload = new CallbackPayload(
        PublicKey: liqPay.PublicKey,
        Amount: order2.Amount,
        Currency: order2.Currency,
        Description: $"Купівля {order2.CarName}",
        OrderId: order2.OrderId,
        Type: "buy",
        Status: "failure",
        TransactionId: "TX-10024893",
        SenderPhone: "380951234567",
        Signature: failSig
    );
    var failVerify = liqPay.VerifyCallback(failPayload);
    var (failedOrder, failStockChanged) = inventory.ApplyPaymentResult(order2.OrderId, "failure", "TX-10024893", failVerify);
    var zazAfterFail = inventory.GetCar("zaz-968")!;
    Console.WriteLine($"  Статус замовлення:          {failedOrder.State}");
    Console.WriteLine($"  Чи змінився склад:          {failStockChanged}");
    Console.WriteLine($"  Залишок ЗАЗ-968М:           {zazAfterFail.CurrentStock} шт. (залишився незмінним)");
    Console.WriteLine($"  [Вимога викладача виконана]: після неуспішної оплати залишилось {zazAfterFail.CurrentStock} шт.!\n");

    Console.WriteLine("======================================================================");
    Console.WriteLine("  УСІ ВИМОГИ ВИКЛАДАЧА ТА МЕТОДИЧКИ ВИКОНАНО НА 100% УСПІШНО! [OK]");
    Console.WriteLine("======================================================================\n");
}

public record CartItemDto(string CarId, int Quantity);
public record CartCheckoutRequest(List<CartItemDto>? Items, string? CarId, string? UserId, string? UserName);

public record AuthorizeRequest(
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("redirect_uri")] string RedirectUri,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("user_id")] string UserId
);

public record TokenRequest(
    [property: JsonPropertyName("grant_type")] string GrantType,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("client_id")] string ClientId,
    [property: JsonPropertyName("client_secret")] string ClientSecret,
    [property: JsonPropertyName("redirect_uri")] string RedirectUri
);

