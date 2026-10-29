#!/usr/bin/env dotnet-run
#:include RoundState.cs
#:include DesTables.cs
#:include DesEngine.cs

using System;
using System.Collections.Generic;
using System.Text;

namespace DesCipher;

public class Program
{
    public static bool NonInteractive = false;

    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length > 0 && (args[0].ToLowerInvariant() == "--demo" || args[0].ToLowerInvariant() == "-d"))
        {
            NonInteractive = true;
            RunBrigadeDemo();
            HandleWeakKeysCheck();
            HandleAvalancheTest();
            return;
        }

        while (true)
        {
            Console.Clear();
            Console.WriteLine("======================================================================");
            Console.WriteLine("       ЛАБОРАТОРНА РОБОТА №1: АЛГОРИТМ ШИФРУВАННЯ DES (.NET)");
            Console.WriteLine("       Кафедра ПІ, ХНУРЕ | Дисципліна: Безпека програм та даних");
            Console.WriteLine("       Бригада: Чуваєв А. О. (вар. 16), Світенко С. М. (вар. 13)");
            Console.WriteLine("======================================================================");
            Console.WriteLine(" 1. Зашифрувати текст (з детальним розрахунком ентропії по раундах)");
            Console.WriteLine(" 2. Розшифрувати шифротекст (Hex / Base64)");
            Console.WriteLine(" 3. Запустити демонстрацію для бригади (Варіанти 16 та 13)");
            Console.WriteLine(" 4. Перевірка на слабкі та напівслабкі ключі DES");
            Console.WriteLine(" 5. Дослідження лавинного ефекту (Avalanche Effect)");
            Console.WriteLine(" 0. Вихід");
            Console.WriteLine("======================================================================");
            Console.Write("Оберіть пункт меню [0-5]: ");

            string? choice = Console.ReadLine()?.Trim();
            if (choice == "0") break;

            switch (choice)
            {
                case "1":
                    HandleEncrypt();
                    break;
                case "2":
                    HandleDecrypt();
                    break;
                case "3":
                    RunBrigadeDemo();
                    break;
                case "4":
                    HandleWeakKeysCheck();
                    break;
                case "5":
                    HandleAvalancheTest();
                    break;
                default:
                    Console.WriteLine("\n[!] Невірний вибір. Натисніть Enter...");
                    Console.ReadLine();
                    break;
            }
        }
    }

    private static void HandleEncrypt()
    {
        Console.WriteLine("\n--- ШИФРУВАННЯ ТЕКСТУ (DES) ---");
        Console.Write("Введіть відкритий текст: ");
        string? text = Console.ReadLine();
        if (string.IsNullOrEmpty(text))
        {
            Console.WriteLine("Текст не може бути порожнім!");
            Pause();
            return;
        }

        Console.Write("Введіть ключ (8 символів ASCII або порожній для автогенерації): ");
        string? keyStr = Console.ReadLine();
        if (string.IsNullOrEmpty(keyStr))
            keyStr = "BPTD2026"; // 8 символів

        byte[] keyBytes = Encoding.UTF8.GetBytes(keyStr.PadRight(8, '0')[..8]);
        ulong key64 = DesEngine.BytesToUlongBigEndian(keyBytes, 0);

        var weakCheck = DesEngine.CheckWeakKey(key64);
        if (weakCheck.IsWeak)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[ПОПЕРЕДЖЕННЯ СИСТЕМИ БЕЗПЕКИ]: Введений ключ є слабким: {weakCheck.Description}!");
            Console.ResetColor();
        }

        Console.WriteLine($"\nКлюч (Hex): 0x{key64:X16} (текст: \"{Encoding.UTF8.GetString(keyBytes)}\")");
        string cipherHex = DesEngine.EncryptText(text, keyBytes, out var allBlockStates);

        Console.WriteLine($"\nЗашифрований текст (Hex): {cipherHex}");
        byte[] cipherBytes = DesEngine.HexToBytes(cipherHex);
        Console.WriteLine($"Зашифрований текст (Base64): {Convert.ToBase64String(cipherBytes)}");

        Console.WriteLine($"\nКількість 64-бітних блоків: {allBlockStates.Count}");
        for (int b = 0; b < allBlockStates.Count; b++)
        {
            Console.WriteLine($"\n=== ТАБЛИЦЯ ЕНТРОПІЇ ДЛЯ БЛОКУ #{b + 1} ===");
            PrintEntropyTable(allBlockStates[b]);
        }

        Pause();
    }

    private static void HandleDecrypt()
    {
        Console.WriteLine("\n--- ДЕШИФРУВАННЯ ТЕКСТУ (DES) ---");
        Console.WriteLine("Оберіть формат шифротексту: 1 - Hex, 2 - Base64");
        Console.Write("Вибір [1-2]: ");
        string? fmt = Console.ReadLine()?.Trim();

        Console.Write("Введіть шифротекст: ");
        string? cipherInput = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(cipherInput))
        {
            Console.WriteLine("Шифротекст не може бути порожнім!");
            Pause();
            return;
        }

        string hex = cipherInput;
        if (fmt == "2")
        {
            try
            {
                byte[] raw = Convert.FromBase64String(cipherInput);
                hex = DesEngine.BytesToHex(raw);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Помилка декодування Base64: {ex.Message}");
                Pause();
                return;
            }
        }

        Console.Write("Введіть ключ (8 символів ASCII): ");
        string? keyStr = Console.ReadLine();
        if (string.IsNullOrEmpty(keyStr))
            keyStr = "BPTD2026";

        byte[] keyBytes = Encoding.UTF8.GetBytes(keyStr.PadRight(8, '0')[..8]);

        try
        {
            string plainText = DesEngine.DecryptText(hex, keyBytes);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\nРозшифрований оригінальний текст: \"{plainText}\"");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Помилка дешифрування: {ex.Message}. Можливо, вказано невірний ключ або шифротекст пошкоджено.");
            Console.ResetColor();
        }

        Pause();
    }

    private static void RunBrigadeDemo()
    {
        Console.WriteLine("\n======================================================================");
        Console.WriteLine("    АВТОМАТИЧНА ДЕМОНСТРАЦІЯ ДЛЯ БРИГАДИ (ВАРІАНТИ 16 ТА 13)");
        Console.WriteLine("======================================================================");

        // Студент 1: Чуваєв А. О. (Варіант 16)
        Console.WriteLine("\n--- [1] СТУДЕНТ 1: Чуваєв А. О. (Варіант 16) ---");
        string text16 = "Чуваєв Артем (вар. 16): Алгоритм DES успішно реалізовано без бібліотек!";
        byte[] key16 = Encoding.UTF8.GetBytes("Chuv16Key"[..8]); // 8 байт
        ulong key16_u64 = DesEngine.BytesToUlongBigEndian(key16, 0);
        Console.WriteLine($"Відкритий текст: \"{text16}\"");
        Console.WriteLine($"Ключ:            \"{Encoding.UTF8.GetString(key16)}\" (0x{key16_u64:X16})");

        string cipherHex16 = DesEngine.EncryptText(text16, key16, out var states16);
        Console.WriteLine($"Шифротекст (Hex):    {cipherHex16}");
        Console.WriteLine($"Шифротекст (Base64): {Convert.ToBase64String(DesEngine.HexToBytes(cipherHex16))}");

        string decText16 = Encoding.UTF8.GetString(DesEngine.DecryptBytes(DesEngine.HexToBytes(cipherHex16), key16));
        Console.WriteLine($"Розшифровано:    \"{decText16}\"");
        Console.WriteLine($"Збіг даних:      {text16 == decText16} (100% відповідність)");

        Console.WriteLine("\nТаблиця розрахунку ентропії появи одиниці (p1) по раундах (Блок #1):");
        PrintEntropyTable(states16[0]);

        // Студент 2: Світенко С. М. (Варіант 13)
        Console.WriteLine("\n----------------------------------------------------------------------");
        Console.WriteLine("--- [2] СТУДЕНТ 2: Світенко С. М. (Варіант 13) ---");
        string text13 = "Світенко Софія (вар. 13): 16 раундів мережі Фейстеля забезпечують баланс ентропії.";
        byte[] key13 = Encoding.UTF8.GetBytes("Sofi13Key"[..8]); // 8 байт
        ulong key13_u64 = DesEngine.BytesToUlongBigEndian(key13, 0);
        Console.WriteLine($"Відкритий текст: \"{text13}\"");
        Console.WriteLine($"Ключ:            \"{Encoding.UTF8.GetString(key13)}\" (0x{key13_u64:X16})");

        string cipherHex13 = DesEngine.EncryptText(text13, key13, out var states13);
        Console.WriteLine($"Шифротекст (Hex):    {cipherHex13}");
        Console.WriteLine($"Шифротекст (Base64): {Convert.ToBase64String(DesEngine.HexToBytes(cipherHex13))}");

        string decText13 = Encoding.UTF8.GetString(DesEngine.DecryptBytes(DesEngine.HexToBytes(cipherHex13), key13));
        Console.WriteLine($"Розшифровано:    \"{decText13}\"");
        Console.WriteLine($"Збіг даних:      {text13 == decText13} (100% відповідність)");

        Console.WriteLine("\nТаблиця розрахунку ентропії появи одиниці (p1) по раундах (Блок #1):");
        PrintEntropyTable(states13[0]);

        Pause();
    }

    private static void HandleWeakKeysCheck()
    {
        Console.WriteLine("\n======================================================================");
        Console.WriteLine("         ПЕРЕВІРКА НА СЛАБКІ ТА НАПІВСЛАБКІ КЛЮЧІ DES");
        Console.WriteLine("======================================================================");

        Console.WriteLine("\n[1] Перевірка відомих слабких ключів (Weak Keys):");
        ulong[] knownWeak = { 0x0101010101010101UL, 0xFEFEFEFEFEFEFEFEUL, 0x1F1F1F1F0E0E0E0EUL, 0xE0E0E0E0F1F1F1F1UL };
        foreach (var wk in knownWeak)
        {
            var res = DesEngine.CheckWeakKey(wk);
            Console.WriteLine($"Ключ 0x{wk:X16}: {res.Description} (IsWeak = {res.IsWeak})");
        }

        Console.WriteLine("\n[2] Перевірка відомих напівслабких ключів (Semi-Weak Keys):");
        ulong[] knownSemiWeak = { 0x01FE01FE01FE01FEUL, 0x1FE01FE00EF10EF1UL, 0x01E001E001F101F1UL };
        foreach (var swk in knownSemiWeak)
        {
            var res = DesEngine.CheckWeakKey(swk);
            Console.WriteLine($"Ключ 0x{swk:X16}: {res.Description} (IsWeak = {res.IsWeak})");
        }

        Console.WriteLine("\n[3] Перевірка звичайного робочого ключа (0x4368757631364B65):");
        var norm = DesEngine.CheckWeakKey(0x4368757631364B65UL);
        Console.WriteLine($"Ключ 0x4368757631364B65: {norm.Description} (IsWeak = {norm.IsWeak})");

        Pause();
    }

    private static void HandleAvalancheTest()
    {
        Console.WriteLine("\n======================================================================");
        Console.WriteLine("           ДОСЛІДЖЕННЯ ЛАВИННОГО ЕФЕКТУ (AVALANCHE EFFECT)");
        Console.WriteLine("======================================================================");
        Console.WriteLine("Лавинний ефект демонструє, як зміна всього 1 біта у відкритому тексті");
        Console.WriteLine("призводить до зміни ~50% бітів у результуючому шифротексті.\n");

        ulong block1 = 0x0123456789ABCDEFUL;
        ulong block2 = 0x0123456789ABCDEEUL; // відрізняється 1 молодшим бітом
        ulong key = 0x133457799BBCDFF1UL;

        var subkeys = DesEngine.GenerateSubkeys(key);
        var states1 = new List<RoundState>();
        var states2 = new List<RoundState>();

        ulong c1 = DesEngine.EncryptBlock(block1, subkeys, states1);
        ulong c2 = DesEngine.EncryptBlock(block2, subkeys, states2);

        Console.WriteLine($"Блок 1: 0x{block1:X16}");
        Console.WriteLine($"Блок 2: 0x{block2:X16} (відмінність: 1 біт)");
        Console.WriteLine($"Ключ:   0x{key:X16}\n");

        Console.WriteLine("----------------------------------------------------------------------");
        Console.WriteLine("Раунд | Стан Блоку 1 (Hex) | Стан Блоку 2 (Hex) | Змінено біт | % зміни");
        Console.WriteLine("----------------------------------------------------------------------");

        for (int i = 0; i < states1.Count; i++)
        {
            ulong diff = states1[i].FullBlock ^ states2[i].FullBlock;
            int bitDiff = DesEngine.CountOnes(diff);
            double pct = (double)bitDiff / 64.0 * 100.0;
            Console.WriteLine($"{states1[i].StageName,-6} | 0x{states1[i].FullBlock:X16} | 0x{states2[i].FullBlock:X16} | {bitDiff,11} | {pct,7:F1}%");
        }

        Console.WriteLine("----------------------------------------------------------------------");
        int totalDiff = DesEngine.CountOnes(c1 ^ c2);
        Console.WriteLine($"Підсумок: Шифротекст 1 = 0x{c1:X16}, Шифротекст 2 = 0x{c2:X16}");
        Console.WriteLine($"Загалом змінилося бітів: {totalDiff} з 64 ({(double)totalDiff / 64.0 * 100.0:F1}%)");

        Pause();
    }

    private static void PrintEntropyTable(List<RoundState> states)
    {
        Console.WriteLine("+-------+----------------------------------+----------+---------+----------+");
        Console.WriteLine("| Раунд | Стан блоку L_i R_i (Hex)         | Одиниць  | p1 (1)  | Ентропія |");
        Console.WriteLine("+-------+----------------------------------+----------+---------+----------+");
        foreach (var s in states)
        {
            Console.WriteLine($"| {s.StageName,-5} | 0x{s.FullBlock:X16}               | {s.OnesCount,8} | {s.P1,7:F4} | {s.Entropy,7:F4} б| ");
        }
        Console.WriteLine("+-------+----------------------------------+----------+---------+----------+");
    }

    private static void Pause()
    {
        if (NonInteractive || Console.IsInputRedirected)
            return;

        Console.WriteLine("\nНатисніть Enter для продовження...");
        Console.ReadLine();
    }
}
