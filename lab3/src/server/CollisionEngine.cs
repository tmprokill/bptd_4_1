using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Lab3.Server;

public enum FileCategory
{
    Document,
    SourceCode,
    Image,
    Unknown
}

/// <summary>
/// Двигун аналізу та автоматичного формування колізій для різних типів файлів
/// (документи, вихідний код, зображення) за допомогою непомітних модифікацій.
/// </summary>
public static class CollisionEngine
{
    public static FileCategory DetectFileType(string fileNameOrExt) => DetectCategory(fileNameOrExt);

    public static FileCategory DetectCategory(string fileNameOrExt)
    {
        string ext = Path.GetExtension(fileNameOrExt).ToLowerInvariant();
        return ext switch
        {
            ".txt" or ".doc" or ".docx" or ".rtf" or ".pdf" or ".md" => FileCategory.Document,
            ".cs" or ".js" or ".ts" or ".py" or ".cpp" or ".java" or ".html" or ".css" => FileCategory.SourceCode,
            ".png" or ".jpg" or ".jpeg" or ".bmp" or ".gif" or ".webp" => FileCategory.Image,
            _ => FileCategory.Unknown
        };
    }

    /// <summary>
    /// Перевірка ручної колізії між двома файлами користувача.
    /// </summary>
    public static (bool IsCollision, string OrigHash, string ModHash, string Message) VerifyCollision(
        byte[] originalBytes, byte[] modifiedBytes, int bitLength)
    {
        var (origVal, origBin, _) = CustomHasher.ComputeHash(originalBytes, bitLength);
        var (modVal, modBin, _) = CustomHasher.ComputeHash(modifiedBytes, bitLength);

        bool identicalContent = originalBytes.SequenceEqual(modifiedBytes);
        bool hashesMatch = (origVal == modVal);

        if (identicalContent)
        {
            return (false, origBin, modBin, "Файли мають абсолютно однаковий двійковий зміст. Це не є колізією.");
        }

        if (hashesMatch)
        {
            return (true, origBin, modBin, $"КОЛІЗІЮ ПІДТВЕРДЖЕНО! Зміст різний ({originalBytes.Length} vs {modifiedBytes.Length} байт), але хеш-суми однакові ({origBin}).");
        }
        else
        {
            return (false, origBin, modBin, $"Колізії немає: хеш оригіналу = {origBin}, хеш модифікованого = {modBin}.");
        }
    }

    /// <summary>
    /// Автоматичний підбір колізії для вхідного файлу за допомогою непомітних модифікацій
    /// (пробільні символи в кінці документів, коментарі в коді або метадані після IEND у зображеннях).
    /// </summary>
    public static (bool Success, byte[] CollidedBytes, int Attempts, string Description) GenerateStealthCollision(
        byte[] originalBytes, string fileName, int bitLength)
    {
        var targetHash = CustomHasher.ComputeHash(originalBytes, bitLength).Value;
        var category = DetectCategory(fileName);
        int maxAttempts = 10000; // для 8 біт достатньо в середньому 256 спроб

        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            byte[] candidate = MutateFileStealthily(originalBytes, category, attempt);

            // Перевіряємо, чи отримали колізію
            if (!candidate.SequenceEqual(originalBytes))
            {
                int candHash = CustomHasher.ComputeHash(candidate, bitLength).Value;
                if (candHash == targetHash)
                {
                    string desc = category switch
                    {
                        FileCategory.Document => $"Додано непомітні пробільні символи (ітерація {attempt}) в кінці документу",
                        FileCategory.SourceCode => $"Додано невидимий нульовий коментар (salt #{attempt}) у вихідний код",
                        FileCategory.Image => $"Додано безпечний службовий маркер метаданих ({attempt} байт) за межі IEND",
                        _ => $"Додано безпечний суфікс солі (ітерація {attempt})"
                    };
                    return (true, candidate, attempt, desc);
                }
            }
        }

        return (false, originalBytes, maxAttempts, "Не вдалося підібрати колізію за встановлену кількість ітерацій.");
    }

    private static byte[] MutateFileStealthily(byte[] original, FileCategory category, int salt)
    {
        using var ms = new MemoryStream();
        ms.Write(original, 0, original.Length);

        switch (category)
        {
            case FileCategory.Document:
                // Додаємо різноманітні комбінації невидимих пробілів, табуляцій та переносів рядків
                int spaceCount = (salt % 40) + 1;
                int tabCount = (salt / 40) % 6;
                string padding = new string(' ', spaceCount) + new string('\t', tabCount) + ((salt % 3 == 0) ? "\r\n" : ((salt % 3 == 1) ? "\n" : " "));
                byte[] spaceBytes = Encoding.UTF8.GetBytes(padding);
                ms.Write(spaceBytes, 0, spaceBytes.Length);
                break;

            case FileCategory.SourceCode:
                // Додаємо безпечний коментар або пробіл у коді
                string comment = $"\n// [integrity_salt_{salt}]\n";
                byte[] commentBytes = Encoding.UTF8.GetBytes(comment);
                ms.Write(commentBytes, 0, commentBytes.Length);
                break;

            case FileCategory.Image:
                // Додаємо байти в кінець файлу після маркера кінця зображення
                byte[] extraBytes = Encoding.ASCII.GetBytes($"\x00\x00SALT_{salt:X4}");
                ms.Write(extraBytes, 0, extraBytes.Length);
                break;

            default:
                byte[] defaultSalt = Encoding.UTF8.GetBytes($"\x20#{salt}");
                ms.Write(defaultSalt, 0, defaultSalt.Length);
                break;
        }

        return ms.ToArray();
    }
}
