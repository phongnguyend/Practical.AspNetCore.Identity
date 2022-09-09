using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;

namespace AspNetCore.Identity.Extensions
{
    public static class PasswordHasherExtensions
    {
        public static HashDetails? ParseHashedPassword<TUser>(this IPasswordHasher<TUser> passwordHasher, string hashedPassword) where TUser : class
        {
            return ParseHashedPassword(Convert.FromBase64String(hashedPassword));
        }

        private static HashDetails? ParseHashedPassword(byte[] hashedPassword)
        {
            if (hashedPassword[0] == 0)
                return ParseHashedPasswordV2(hashedPassword);
            if (hashedPassword[0] == 1)
                return ParseHashedPasswordV3(hashedPassword);
            return ParseHashedPasswordV3(hashedPassword);
        }

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
                Version = hashedPassword[0],
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

        public static HashDetails? ParseHashedPasswordV3<TUser>(this IPasswordHasher<TUser> passwordHasher, string hashedPassword) where TUser : class
        {
            return ParseHashedPasswordV3(Convert.FromBase64String(hashedPassword));
        }

        private static HashDetails? ParseHashedPasswordV3(byte[] hashedPassword)
        {
            try
            {
                // Read header information
                KeyDerivationPrf prf = (KeyDerivationPrf)ReadNetworkByteOrder(hashedPassword, 1);
                int iterCount = (int)ReadNetworkByteOrder(hashedPassword, 5);
                int saltLength = (int)ReadNetworkByteOrder(hashedPassword, 9);

                // Read the salt: must be >= 128 bits
                if (saltLength < 128 / 8)
                {
                    return null;
                }
                byte[] salt = new byte[saltLength];
                Buffer.BlockCopy(hashedPassword, 13, salt, 0, salt.Length);

                // Read the subkey (the rest of the payload): must be >= 128 bits
                int subkeyLength = hashedPassword.Length - 13 - salt.Length;
                if (subkeyLength < 128 / 8)
                {
                    return null;
                }
                byte[] expectedSubkey = new byte[subkeyLength];
                Buffer.BlockCopy(hashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

                return new HashDetails
                {
                    Version = hashedPassword[0],
                    SaltBytes = salt,
                    HashBytes = expectedSubkey,
                    SaltString = Convert.ToBase64String(salt),
                    HashString = Convert.ToBase64String(expectedSubkey),
                    Interations = iterCount,
                    KeyDerivationPrf = prf
                };
            }
            catch
            {
                return null;
            }
        }

        public static string HashPasswordV3<TUser>(this IPasswordHasher<TUser> passwordHasher, string password, byte[] salt, int iterations, KeyDerivationPrf keyDerivationPrf) where TUser : class
        {
            var hashAlgorithmName = HashAlgorithmName.SHA1;
            switch (keyDerivationPrf)
            {
                case KeyDerivationPrf.HMACSHA1:
                    hashAlgorithmName = HashAlgorithmName.SHA1;
                    break;
                case KeyDerivationPrf.HMACSHA256:
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    break;
                case KeyDerivationPrf.HMACSHA512:
                    hashAlgorithmName = HashAlgorithmName.SHA512;
                    break;
            }
            return Convert.ToBase64String(new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithmName).GetBytes(32));
        }

        private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)(buffer[offset + 0]) << 24)
                | ((uint)(buffer[offset + 1]) << 16)
                | ((uint)(buffer[offset + 2]) << 8)
                | ((uint)(buffer[offset + 3]));
        }
    }

    public class HashDetails
    {
        public int Version { get; set; }

        public byte[]? SaltBytes { get; set; }

        public byte[]? HashBytes { get; set; }

        public string? SaltString { get; set; }

        public string? HashString { get; set; }

        public int Interations { get; set; }

        public KeyDerivationPrf KeyDerivationPrf { get; set; }
    }
}
