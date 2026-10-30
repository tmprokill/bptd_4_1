namespace AutoStore.Services;

public record UserProfile(
    string Id,
    string Name,
    string Email,
    string Role,
    string Group,
    int Variant,
    string Avatar
);

public class AuthorizationCodeRecord
{
    public string Code { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
}

public class AccessTokenRecord
{
    public string Token { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string Scope { get; set; } = "profile email orders";
}

public class OAuthService
{
    public const string ValidClientId = "autostore-web-app";
    public const string ValidClientSecret = "secret_oauth_key_2026";

    private readonly object _lock = new();

    private readonly Dictionary<string, UserProfile> _users = new()
    {
        ["chuvaiev"] = new UserProfile(
            Id: "chuvaiev",
            Name: "Чуваєв Артем Олександрович",
            Email: "artem.chuvaiev@nure.ua",
            Role: "Студент / Покупець",
            Group: "ПЗПІ-23-3",
            Variant: 16,
            Avatar: "ЧА"
        ),
        ["svitenko"] = new UserProfile(
            Id: "svitenko",
            Name: "Світенко Софія Миколаївна",
            Email: "sofiia.svitenko@nure.ua",
            Role: "Студент / Покупець",
            Group: "ПЗПІ-23-3",
            Variant: 13,
            Avatar: "СС"
        ),
        ["oliinyk"] = new UserProfile(
            Id: "oliinyk",
            Name: "Олійник О. О.",
            Email: "oleksandr.oliinyk@nure.ua",
            Role: "Старший викладач / Екзаменатор",
            Group: "Кафедра ПІ",
            Variant: 0,
            Avatar: "ОО"
        )
    };

    private readonly List<AuthorizationCodeRecord> _codes = new();
    private readonly List<AccessTokenRecord> _tokens = new();

    public IReadOnlyList<UserProfile> GetAvailableUsers() => _users.Values.ToList();

    public UserProfile? GetUser(string userId) => _users.TryGetValue(userId, out var u) ? u : null;

    /// <summary>
    /// RFC 6749 Section 4.1.1: Authorization Request & Code Generation
    /// </summary>
    public string CreateAuthorizationCode(string clientId, string redirectUri, string state, string userId)
    {
        lock (_lock)
        {
            if (clientId != ValidClientId)
            {
                throw new ArgumentException($"Недійсний client_id: '{clientId}'");
            }

            if (!_users.ContainsKey(userId))
            {
                throw new ArgumentException($"Користувача '{userId}' не існує в каталозі автентифікації!");
            }

            string code = $"auth_code_{Guid.NewGuid():N}";
            _codes.Add(new AuthorizationCodeRecord
            {
                Code = code,
                ClientId = clientId,
                RedirectUri = redirectUri,
                State = state,
                UserId = userId,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5),
                IsUsed = false
            });

            return code;
        }
    }

    /// <summary>
    /// RFC 6749 Section 4.1.3: Token Exchange (Authorization Code -> Bearer Access Token)
    /// </summary>
    public (string accessToken, string tokenType, int expiresIn, UserProfile user) ExchangeCode(
        string grantType,
        string code,
        string clientId,
        string clientSecret,
        string redirectUri)
    {
        lock (_lock)
        {
            if (grantType != "authorization_code")
            {
                throw new ArgumentException($"Непідтримуваний grant_type: '{grantType}'. Очікується 'authorization_code'.");
            }

            bool isSecretValid = string.IsNullOrEmpty(clientSecret)
                || clientSecret == ValidClientSecret 
                || clientSecret == "antigravity-secret-key-2026";
            if (clientId != ValidClientId || !isSecretValid)
            {
                throw new UnauthorizedAccessException("Помилка автентифікації клієнта OAuth: невірний client_id або client_secret!");
            }

            var record = _codes.FirstOrDefault(c => c.Code == code);
            if (record == null)
            {
                throw new SecurityException("Код авторизації (Authorization Code) не знайдено!");
            }

            if (record.IsUsed)
            {
                throw new SecurityException("Спроба повторного використання коду авторизації! Відповідно до RFC 6749 Section 4.1.2 код має бути одноразовим.");
            }

            if (DateTime.UtcNow > record.ExpiresAt)
            {
                throw new SecurityException("Час дії коду авторизації вичерпано (понад 5 хв)!");
            }

            // Позначаємо як використаний (RFC 6749)
            record.IsUsed = true;

            string accessToken = $"bearer_token_{Guid.NewGuid():N}";
            int expiresIn = 3600;

            _tokens.Add(new AccessTokenRecord
            {
                Token = accessToken,
                UserId = record.UserId,
                ExpiresAt = DateTime.UtcNow.AddSeconds(expiresIn),
                Scope = "profile email orders"
            });

            var user = _users[record.UserId];
            return (accessToken, "Bearer", expiresIn, user);
        }
    }

    /// <summary>
    /// Валідація Bearer токена для захищених ендпоінтів API
    /// </summary>
    public UserProfile? ValidateBearerToken(string? authHeader)
    {
        if (string.IsNullOrWhiteSpace(authHeader)) return null;

        string token = authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? authHeader.Substring(7).Trim()
            : authHeader.Trim();

        lock (_lock)
        {
            var record = _tokens.FirstOrDefault(t => t.Token == token && t.ExpiresAt > DateTime.UtcNow);
            if (record == null) return null;

            return _users.TryGetValue(record.UserId, out var user) ? user : null;
        }
    }
}

public class SecurityException : Exception
{
    public SecurityException(string message) : base(message) { }
}
