using System;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.IO;

public static class CommonUtils
{
    public static string PrettifyJson(string unPrettyJson)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        var jsonElement = JsonSerializer.Deserialize<JsonElement>(unPrettyJson);

        return JsonSerializer.Serialize(jsonElement, options);
    }
    public static double FloorWithDigit(double input, int digits = 0) => double.Parse(input.ToString($"F{digits}"));
    public static string ComputeSha256Hash(string text)
    {
        using var sha256 = new SHA256Managed();
        return BitConverter.ToString(sha256.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-", "");
    }
    public static bool CheckValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
    public static bool CheckPasswordPattern(string password)
    {
        var hasNumber = new Regex(@"[0-9]+");
        var hasUpperChar = new Regex(@"[A-Z]+");
        var hasMiniMaxChars = new Regex(@".{6,12}");
        var hasLowerChar = new Regex(@"[a-z]+");
        var hasSymbols = new Regex(@"[!@#$%^&*()_+=\[{\]};:<>|./?,-]");

        return hasNumber.IsMatch(password) && hasUpperChar.IsMatch(password)
            && hasMiniMaxChars.IsMatch(password) && hasLowerChar.IsMatch(password)
            && hasSymbols.IsMatch(password);
    }
    private static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    public static long ToUnixTime(DateTime date) => Convert.ToInt64((date - epoch).TotalSeconds);
    public static DateTime UnixTimeToDateTime(double unixTime)
    {
        DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        return dateTime.AddMilliseconds(unixTime).ToLocalTime();
    }
    public static string EncryptAes256(string inputText, string password)
    {
        var rijndaelCipher = new RijndaelManaged();

        byte[] plainText = Encoding.Unicode.GetBytes(inputText);
        byte[] salt = Encoding.ASCII.GetBytes(password.Length.ToString());

        var secretKey = new PasswordDeriveBytes(password, salt);
        var encryptor = rijndaelCipher.CreateEncryptor(secretKey.GetBytes(32), secretKey.GetBytes(16));
        var memoryStream = new MemoryStream();

        var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
        cryptoStream.Write(plainText, 0, plainText.Length);
        cryptoStream.FlushFinalBlock();

        byte[] cipherBytes = memoryStream.ToArray();

        memoryStream.Close();
        cryptoStream.Close();

        return Convert.ToBase64String(cipherBytes);
    }
    public static string DecryptAes256(string inputText, string password)
    {
        var rijndaelCipher = new RijndaelManaged();

        byte[] encryptedData = Convert.FromBase64String(inputText);
        byte[] salt = Encoding.ASCII.GetBytes(password.Length.ToString());

        var secretKey = new PasswordDeriveBytes(password, salt);

        var decrypt = rijndaelCipher.CreateDecryptor(secretKey.GetBytes(32), secretKey.GetBytes(16));

        var memoryStream = new MemoryStream(encryptedData);

        var cryptoStream = new CryptoStream(memoryStream, decrypt, CryptoStreamMode.Read);
        var plainText = new byte[encryptedData.Length];

        int decryptedCount = cryptoStream.Read(plainText, 0, plainText.Length);

        memoryStream.Close();
        cryptoStream.Close();

        return Encoding.Unicode.GetString(plainText, 0, decryptedCount);
    }
    public static string GetTimeString(DateTime created_at)
    {
        int offset = DateTimeOffset.Now.Offset.Hours;
        string dateText = created_at.AddHours(offset).ToString();
        var diffTime = DateTime.Now.Subtract(created_at.AddHours(offset));
        if (diffTime.TotalSeconds < 60)
        {
            dateText = "방금 전";
        }
        else if (diffTime.TotalMinutes < 60)
        {
            dateText = ((int)diffTime.TotalMinutes).ToString() + "분 전";
        }
        else if (diffTime.TotalHours < 24)
        {
            dateText = ((int)diffTime.TotalHours).ToString() + "시간 전";
        }
        return dateText;
    }
}