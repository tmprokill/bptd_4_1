namespace DesCipher;

/// <summary>
/// Знімок стану 64-бітного блоку даних на кожному з етапів шифрування (Вхід, IP, Р01..Р16, IP^-1).
/// </summary>
public class RoundState
{
    /// <summary>
    /// Назва етапу (наприклад, "Вхід", "IP", "Р01", ..., "IP^-1").
    /// </summary>
    public string StageName { get; set; } = string.Empty;

    /// <summary>
    /// Ліва 32-бітна частина блоку (L_i).
    /// </summary>
    public uint L { get; set; }

    /// <summary>
    /// Права 32-бітна частина блоку (R_i).
    /// </summary>
    public uint R { get; set; }

    /// <summary>
    /// Повний 64-бітний стан блоку (L_i || R_i або стан після перестановки).
    /// </summary>
    public ulong FullBlock { get; set; }

    /// <summary>
    /// Кількість одиничних бітів у 64-бітному блоці.
    /// </summary>
    public int OnesCount { get; set; }

    /// <summary>
    /// Частота (ймовірність) появи одиниці: p1 = OnesCount / 64.
    /// </summary>
    public double P1 { get; set; }

    /// <summary>
    /// Інформаційна ентропія за Шенноном (у бітах): H = -p1*log2(p1) - p0*log2(p0).
    /// </summary>
    public double Entropy { get; set; }
}
