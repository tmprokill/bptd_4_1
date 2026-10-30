namespace AutoStore.Services;

public record CarItem(
    string Id,
    string Name,
    string Model,
    int Year,
    decimal Price,
    string Engine,
    string Description,
    int InitialStock,
    int CurrentStock,
    string BadgeColor
);

public enum OrderState
{
    Pending,
    Paid,
    Failed,
    WaitSecure
}

public record OrderItem(string CarId, string CarName, int Quantity, decimal UnitPrice);

public class OrderRecord
{
    public string OrderId { get; set; } = string.Empty;
    public string CarId { get; set; } = string.Empty;
    public string CarName { get; set; } = string.Empty;
    public List<OrderItem> Items { get; set; } = new();
    public decimal Amount { get; set; }
    public string Currency { get; set; } = "UAH";
    public string? UserId { get; set; }
    public string UserName { get; set; } = "Гість сайту";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public OrderState State { get; set; } = OrderState.Pending;
    public string? TransactionId { get; set; }
    public DateTime? ProcessedAt { get; set; }
    public int StockBefore { get; set; }
    public int StockAfter { get; set; }
    public string LogMessage { get; set; } = string.Empty;
}

public class InventoryService
{
    private readonly object _lock = new();

    private readonly Dictionary<string, CarItem> _cars = new()
    {
        ["zaz-968"] = new CarItem(
            Id: "zaz-968",
            Name: "ЗАЗ-968М «Запорожець»",
            Model: "ЗАЗ-968М",
            Year: 1982,
            Price: 15.00m, // Демонстраційна ціна 15 грн для реальних LiqPay Sandbox транзакцій
            Engine: "МеМЗ-968Е V4, 40 к.с., повітряне охолодження",
            Description: "Культовий автомобіль. За вказівкою викладача: початковий залишок 3 шт. Після успішної оплати стає 2 шт., після неуспішної — 3 шт.",
            InitialStock: 3,
            CurrentStock: 3,
            BadgeColor: "#3b82f6"
        ),
        ["luaz-969"] = new CarItem(
            Id: "luaz-969",
            Name: "ЛуАЗ-969М «Волинь»",
            Model: "ЛуАЗ-969М",
            Year: 1986,
            Price: 25.00m,
            Engine: "МеМЗ-968М 1.2 л, 40 к.с., повний привід 4x4",
            Description: "Український позашляховик підвищеної прохідності з блокуванням заднього диференціала.",
            InitialStock: 2,
            CurrentStock: 2,
            BadgeColor: "#10b981"
        ),
        ["tavria-1102"] = new CarItem(
            Id: "tavria-1102",
            Name: "ЗАЗ-1102 «Таврія Нова»",
            Model: "ЗАЗ-1102",
            Year: 1998,
            Price: 35.00m,
            Engine: "МеМЗ-245 1.1 л, 53 к.с., рідинне охолодження",
            Description: "Передньопривідний хетчбек з економічним споживанням пального.",
            InitialStock: 4,
            CurrentStock: 4,
            BadgeColor: "#8b5cf6"
        )
    };

    private readonly List<OrderRecord> _orders = new();

    public IReadOnlyList<CarItem> GetAllCars()
    {
        lock (_lock)
        {
            return _cars.Values.ToList();
        }
    }

    public CarItem? GetCar(string id)
    {
        lock (_lock)
        {
            return _cars.TryGetValue(id, out var car) ? car : null;
        }
    }

    public OrderRecord CreateOrder(string carId, string? userId, string? userName)
    {
        return CreateOrderFromCart(new List<(string carId, int quantity)> { (carId, 1) }, userId, userName);
    }

    public OrderRecord CreateOrderFromCart(List<(string carId, int quantity)> cartItems, string? userId, string? userName)
    {
        lock (_lock)
        {
            if (cartItems == null || cartItems.Count == 0)
            {
                throw new InvalidOperationException("Кошик порожній! Оберіть хоча б один автомобіль.");
            }

            var orderItems = new List<OrderItem>();
            decimal totalAmount = 0;

            foreach (var (carId, qty) in cartItems)
            {
                if (!_cars.TryGetValue(carId, out var car))
                {
                    throw new InvalidOperationException($"Автомобіль з ID '{carId}' не знайдено!");
                }

                if (car.CurrentStock < qty)
                {
                    throw new InvalidOperationException($"Недостатньо автомобілів '{car.Name}' на складі! Доступно: {car.CurrentStock} шт., запитано: {qty} шт.");
                }

                orderItems.Add(new OrderItem(car.Id, car.Name, qty, car.Price));
                totalAmount += car.Price * qty;
            }

            var primaryCar = _cars[orderItems[0].CarId];
            string orderId = $"ORD-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Random.Shared.Next(100, 999)}";
            string title = orderItems.Count == 1 
                ? orderItems[0].CarName 
                : $"{orderItems[0].CarName} + ще {orderItems.Count - 1} авто";

            var order = new OrderRecord
            {
                OrderId = orderId,
                CarId = primaryCar.Id,
                CarName = title,
                Items = orderItems,
                Amount = totalAmount,
                Currency = "UAH",
                UserId = userId,
                UserName = string.IsNullOrWhiteSpace(userName) ? "Гість" : userName,
                CreatedAt = DateTime.UtcNow,
                State = OrderState.Pending,
                StockBefore = primaryCar.CurrentStock,
                StockAfter = primaryCar.CurrentStock,
                LogMessage = $"Замовлення сформовано з кошика. Очікується оплата через LiqPay."
            };

            _orders.Add(order);
            return order;
        }
    }

    public OrderRecord? GetOrder(string orderId)
    {
        lock (_lock)
        {
            return _orders.FirstOrDefault(o => o.OrderId == orderId);
        }
    }

    public IReadOnlyList<OrderRecord> GetOrders(string? userId = null)
    {
        lock (_lock)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return _orders.OrderByDescending(o => o.CreatedAt).ToList();
            }
            return _orders.Where(o => o.UserId == userId).OrderByDescending(o => o.CreatedAt).ToList();
        }
    }

    /// <summary>
    /// Обробка результатів оплати від LiqPay.
    /// Реалізує вимогу викладача:
    /// - Успішна оплата: залишок 3 шт. -> 2 шт.
    /// - Неуспішна оплата: залишок залишається 3 шт.
    /// - Захист від повторного списання (ідемпотентність за orderId).
    /// </summary>
    public (OrderRecord order, bool stockChanged) ApplyPaymentResult(
        string orderId,
        string status,
        string transactionId,
        SignatureVerificationResult sigResult)
    {
        lock (_lock)
        {
            var order = _orders.FirstOrDefault(o => o.OrderId == orderId);
            if (order == null)
            {
                throw new KeyNotFoundException($"Замовлення {orderId} не знайдено у базі даних магазину!");
            }

            if (!sigResult.IsValid)
            {
                order.LogMessage = $"[ALARM Спроба зламу] Підпис LiqPay не валідний! Стан замовлення та склад не змінено.";
                return (order, false);
            }

            if (order.State == OrderState.Paid)
            {
                order.LogMessage = $"[Ідемпотентність] Замовлення {orderId} вже було оплачено раніше. Повторне списання відхилено.";
                return (order, false);
            }

            order.TransactionId = transactionId;
            order.ProcessedAt = DateTime.UtcNow;

            var primaryCar = _cars.TryGetValue(order.CarId, out var pc) ? pc : _cars.Values.First();
            order.StockBefore = primaryCar.CurrentStock;

            bool stockChanged = false;

            bool isSuccess = status.Equals("success", StringComparison.OrdinalIgnoreCase) 
                          || status.Equals("sandbox", StringComparison.OrdinalIgnoreCase);

            if (isSuccess)
            {
                order.State = OrderState.Paid;

                foreach (var item in order.Items)
                {
                    if (_cars.TryGetValue(item.CarId, out var car))
                    {
                        int newStock = Math.Max(0, car.CurrentStock - item.Quantity);
                        _cars[item.CarId] = car with { CurrentStock = newStock };
                        if (item.CarId == primaryCar.Id)
                        {
                            order.StockAfter = newStock;
                        }
                    }
                }

                stockChanged = true;
                order.LogMessage = $"✓ [Успішна оплата LiqPay] Транзакція #{transactionId}. Залишок '{primaryCar.Name}' зменшено з {order.StockBefore} до {order.StockAfter} шт.";
            }
            else if (status.Equals("failure", StringComparison.OrdinalIgnoreCase))
            {
                order.State = OrderState.Failed;
                order.StockAfter = primaryCar.CurrentStock;
                order.LogMessage = $"✗ [Оплату відхилено] Транзакція #{transactionId} відхилена LiqPay. Залишок '{primaryCar.Name}' не змінився: {order.StockAfter} шт.";
            }
            else if (status.Equals("wait_secure", StringComparison.OrdinalIgnoreCase))
            {
                order.State = OrderState.WaitSecure;
                order.StockAfter = primaryCar.CurrentStock;
                order.LogMessage = $"⏳ [3-D Secure] Платіж #{transactionId} на верифікації LiqPay. Залишок '{primaryCar.Name}': {order.StockAfter} шт.";
            }

            return (order, stockChanged);
        }
    }

    public void ResetInventory()
    {
        lock (_lock)
        {
            foreach (var key in _cars.Keys.ToList())
            {
                var car = _cars[key];
                _cars[key] = car with { CurrentStock = car.InitialStock };
            }
            _orders.Clear();
        }
    }
}
