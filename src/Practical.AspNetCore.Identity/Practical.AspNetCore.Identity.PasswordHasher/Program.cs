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

        private static bool VerifyHashedPasswordV3(byte[] hashedPassword, string password)
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
                    return false;
                }
                byte[] salt = new byte[saltLength];
                Buffer.BlockCopy(hashedPassword, 13, salt, 0, salt.Length);

                // Read the subkey (the rest of the payload): must be >= 128 bits
                int subkeyLength = hashedPassword.Length - 13 - salt.Length;
                if (subkeyLength < 128 / 8)
                {
                    return false;
                }
                byte[] expectedSubkey = new byte[subkeyLength];
                Buffer.BlockCopy(hashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

                // Hash the incoming password and verify it
                byte[] actualSubkey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, subkeyLength);

                return CryptographicOperations.FixedTimeEquals(actualSubkey, expectedSubkey);
            }
            catch
            {
                // This should never occur except in the case of a malformed payload, where
                // we might go off the end of the array. Regardless, a malformed payload
                // implies verification failed.
                return false;
            }
        }

        private static bool VerifyHashedPasswordV3(string hashedPassword, string password)
        {
            byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);
            return VerifyHashedPasswordV3(decodedHashedPassword, password);
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

        private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)(buffer[offset + 0]) << 24)
                | ((uint)(buffer[offset + 1]) << 16)
                | ((uint)(buffer[offset + 2]) << 8)
                | ((uint)(buffer[offset + 3]));
        }

        static void Main(string[] args)
        {
            V2();
            V3();
        }

        private static void V2()
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

            var parsed3 = passwordHasher.ParseHashedPassword(hashedPassword1);
            var parsed4 = passwordHasher.ParseHashedPassword(hashedPassword2);
        }

        private static void V3()
        {
            var passwordHasher = new PasswordHasher<object>(Options.Create(new PasswordHasherOptions { CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3 }));
            var password1 = passwordHasher.HashPassword(null, "phongtest123");
            var password2 = passwordHasher.HashPassword(null, "phongtest123");

            var hashedPassword1 = "AQAAAAEAACcQAAAAEK8BtdVA98QGEu7kORnXMTUf1JfuXdqcmqzG1PkK9QVRhrUmwnsK+SoYppOnnFDFDQ==";
            var hashedPassword2 = "AQAAAAEAACcQAAAAEDoO/1NMGyKMYovHoyoPntKPJoH4IGsLZjUIHAXktwA6iA+jGuzDB1ceR3zE+ipZsg==";

            var check1 = passwordHasher.VerifyHashedPassword(null, hashedPassword1, "phongtest123");
            var check2 = passwordHasher.VerifyHashedPassword(null, hashedPassword2, "phongtest123");

            var check3 = VerifyHashedPasswordV3(hashedPassword1, "phongtest123");
            var check4 = VerifyHashedPasswordV3(hashedPassword2, "phongtest123");

            var parsed1 = passwordHasher.ParseHashedPasswordV3(hashedPassword1);
            var parsed2 = passwordHasher.ParseHashedPasswordV3(hashedPassword2);

            var hashedPassword11 = passwordHasher.HashPasswordV3("phongtest123", parsed1.SaltBytes, parsed1.Interations, parsed1.KeyDerivationPrf);
            var hashedPassword22 = passwordHasher.HashPasswordV3("phongtest123", parsed2.SaltBytes, parsed2.Interations, parsed2.KeyDerivationPrf);

            var parsed3 = passwordHasher.ParseHashedPassword(hashedPassword1);
            var parsed4 = passwordHasher.ParseHashedPassword(hashedPassword2);
        }
    }
}