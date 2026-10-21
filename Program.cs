using System.Text;
using AesCtrDemo;

// Ключ AES-256 (32 байти) та IV / початковий лічильник (16 байт).
// Ті самі значення, що й у прикладі CBC зі статті — щоб було зручно порівнювати.
byte[] key =
{
    0x9f, 0xbd, 0xe6, 0x4f, 0xad, 0xe1, 0xf3, 0x9d,
    0x5e, 0x53, 0x7f, 0xbb, 0x92, 0x96, 0x85, 0x10,
    0x9f, 0xbd, 0xe6, 0x4f, 0xad, 0xe1, 0xf3, 0x9d,
    0x5e, 0x53, 0x7f, 0xbb, 0x92, 0x96, 0x85, 0x10
};
byte[] iv =
{
    0xd7, 0xc9, 0xc5, 0xaf, 0x7f, 0xd1, 0xe8, 0x9e,
    0x83, 0xbe, 0x8c, 0xa9, 0xac, 0x7e, 0xd0, 0x00
};

// Навмисно беремо текст, не кратний 16 байтам, щоб показати:
// у CTR доповнення не потрібне.
string message = "Hello it s Aymen — CTR mode works with any length!";
byte[] plaintext = Encoding.UTF8.GetBytes(message);

Console.WriteLine($"Відкритий текст : {message}");
Console.WriteLine($"Довжина         : {plaintext.Length} байт\n");

// --- Зашифрування ---
byte[] encrypted = AesCtrCipher.Encrypt(plaintext, key, iv);
Console.WriteLine($"Зашифровано (hex): {Convert.ToHexString(encrypted)}\n");

// --- Розшифрування ---
byte[] decrypted = AesCtrCipher.Decrypt(encrypted, key, iv);
string recovered = Encoding.UTF8.GetString(decrypted);
Console.WriteLine($"Розшифровано    : {recovered}");

// --- Перевірка ---
bool ok = recovered == message;
Console.WriteLine($"\nСпівпадіння з оригіналом: {(ok ? "ТАК" : "НІ")}");
Environment.Exit(ok ? 0 : 1);
