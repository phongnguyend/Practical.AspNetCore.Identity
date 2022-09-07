using AspNetCore.Identity.Extensions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Practical.AspNetCore.Identity.PasswordHasher
{
    /// <summary>
    /// https://github.com/dotnet/aspnetcore/blob/main/src/Identity/Extensions.Core/src/PasswordHasher.cs
    /// </summary>
    internal class Program
    {
        private static bool VerifyHashedPasswordV2(byte[] hashedPassword, string password)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // We know ahead of time the exact length of a valid hashed password payload.
            if (hashedPassword.Length != 1 + SaltSize + Pbkdf2SubkeyLength)
            {
                return false; // bad size
            }

            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPassword, 1, salt, 0, salt.Length);

            byte[] expectedSubkey = new byte[Pbkdf2SubkeyLength];
            Buffer.BlockCopy(hashedPassword, 1 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

            var test = new Rfc2898DeriveBytes(password, salt, Pbkdf2IterCount);

            var saltString = Convert.ToBase64String(salt);
            var expectedSubkeyString = Convert.ToBase64String(expectedSubkey);

            // Hash the incoming password and verify it
            byte[] actualSubkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);
            byte[] actualSubkey2 = new Rfc2898DeriveBytes(password, salt, Pbkdf2IterCount, HashAlgorithmName.SHA1).GetBytes(Pbkdf2SubkeyLength);
            return ByteArraysEqual(actualSubkey, expectedSubkey) && ByteArraysEqual(actualSubkey, actualSubkey2);
        }

        private static bool VerifyHashedPasswordV2(string hashedPassword, string password)
        {
            byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);
            return VerifyHashedPasswordV2(decodedHashedPassword, password);
        }

        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null)
            {
                return true;
            }
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }

        static void Main(string[] args)
        {
            var passwordHasher = new PasswordHasher<object>(Options.Create(new PasswordHasherOptions { CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV2 }));
            var password1 = passwordHasher.HashPassword(null, "phongtest123");
            var password2 = passwordHasher.HashPassword(null, "phongtest123");

            var hashedPassword1 = "AEm8O/TD+tishk0zxnlrv5aoQ2GC2TC6yLHzb6294JVNxNDoBbWrDnqAJUU4vbtdpQ==";
            var hashedPassword2 = "ABe46ZMkz6U/p6BgKqoBOOM63fU5bScggdS9eza5y9UbQjSSUrOD6VTOppjJWVXvEA==";

            var check1 = passwordHasher.VerifyHashedPassword(null, hashedPassword1, "phongtest123");
            var check2 = passwordHasher.VerifyHashedPassword(null, hashedPassword2, "phongtest123");

            var check3 = VerifyHashedPasswordV2(hashedPassword1, "phongtest123");
            var check4 = VerifyHashedPasswordV2(hashedPassword2, "phongtest123");

            var parsed1 = passwordHasher.ParseHashedPasswordV2(hashedPassword1);
            var parsed2 = passwordHasher.ParseHashedPasswordV2(hashedPassword2);

            var hashedPassword11 = passwordHasher.HashPasswordV2("phongtest123", parsed1.SaltBytes);
            var hashedPassword22 = passwordHasher.HashPasswordV2("phongtest123", parsed2.SaltBytes);
        }
    }
}