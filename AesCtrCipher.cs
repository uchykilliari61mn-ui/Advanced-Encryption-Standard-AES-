using System.Security.Cryptography;

namespace AesCtrDemo;

/// <summary>
/// Власна реалізація режиму CTR (Counter) поверх AES.
///
/// AES тут використовується лише як блочний шифр (ECB на одному 16-байтовому
/// блоці). Сам режим CTR побудований вручну:
///
///   keystream_i = AES_Encrypt(counter_i)
///   cipher_i    = plain_i  XOR keystream_i
///   plain_i     = cipher_i XOR keystream_i
///
/// Через це зашифрування та розшифрування — одна й та сама операція.
/// Доповнення (padding) не потрібне: останній блок XOR-иться лише на свою довжину.
/// </summary>
public static class AesCtrCipher
{
    private const int BlockSize = 16; // AES завжди має блок 128 біт = 16 байт

    /// <summary>Зашифрувати дані в режимі CTR.</summary>
    public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv) => Process(data, key, iv);

    /// <summary>Розшифрувати дані в режимі CTR (операція ідентична зашифруванню).</summary>
    public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv) => Process(data, key, iv);

    private static byte[] Process(byte[] data, byte[] key, byte[] iv)
    {
        if (iv is null || iv.Length != BlockSize)
            throw new ArgumentException($"IV має бути завдовжки {BlockSize} байт.", nameof(iv));

        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;        // шифруємо по одному блоку
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();

        var counter = (byte[])iv.Clone();   // початковий лічильник = IV (не псуємо вхідний IV)
        var result = new byte[data.Length];
        var keystream = new byte[BlockSize];

        for (int offset = 0; offset < data.Length; offset += BlockSize)
        {
            // keystream = AES_Encrypt(counter)
            encryptor.TransformBlock(counter, 0, BlockSize, keystream, 0);

            // XOR відкритого/зашифрованого тексту з потоком ключа
            int blockLen = Math.Min(BlockSize, data.Length - offset);
            for (int i = 0; i < blockLen; i++)
                result[offset + i] = (byte)(data[offset + i] ^ keystream[i]);

            IncrementCounter(counter); // наступне значення лічильника
        }

        return result;
    }

    /// <summary>Інкремент 16-байтового лічильника як big-endian числа.</summary>
    private static void IncrementCounter(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0) break; // немає переносу — зупиняємось
        }
    }
}
