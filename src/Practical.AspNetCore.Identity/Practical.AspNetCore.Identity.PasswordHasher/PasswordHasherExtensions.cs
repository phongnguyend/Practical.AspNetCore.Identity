using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using System;
using System.Security.Cryptography;

namespace AspNetCore.Identity.Extensions
{
    public static class PasswordHasherExtensions
    {
        public static HashDetails? ParseHashedPasswordV2<TUser>(this IPasswordHasher<TUser> passwordHasher, string hashedPassword) where TUser : class
        {
            return ParseHashedPasswordV2(Convert.FromBase64String(hashedPassword));
        }

        private static HashDetails? ParseHashedPasswordV2(byte[] hashedPassword)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // We know ahead of time the exact length of a valid hashed password payload.
            if (hashedPassword.Length != 1 + SaltSize + Pbkdf2SubkeyLength)
            {
                return null; // bad size
            }

            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPassword, 1, salt, 0, salt.Length);

            byte[] expectedSubkey = new byte[Pbkdf2SubkeyLength];
            Buffer.BlockCopy(hashedPassword, 1 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

            return new HashDetails
            {
                SaltBytes = salt,
                HashBytes = expectedSubkey,
                SaltString = Convert.ToBase64String(salt),
                HashString = Convert.ToBase64String(expectedSubkey),
                Interations = Pbkdf2IterCount,
                KeyDerivationPrf = Pbkdf2Prf
            };
        }

        public static string HashPasswordV2<TUser>(this IPasswordHasher<TUser> passwordHasher, string password, byte[] salt) where TUser : class
        {
            return Convert.ToBase64String(new Rfc2898DeriveBytes(password, salt, 1000, HashAlgorithmName.SHA1).GetBytes(32));
        }
    }

    public class HashDetails
    {
        public byte[]? SaltBytes { get; set; }

        public byte[]? HashBytes { get; set; }

        public string? SaltString { get; set; }

        public string? HashString { get; set; }

        public int Interations { get; set; }

        public KeyDerivationPrf KeyDerivationPrf { get; set; }
    }
}
