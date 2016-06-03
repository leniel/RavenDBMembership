namespace RavenDBMembership
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    public static class PasswordUtil
    {
        public static string CreateRandomSalt()
        {
            byte[] data = new byte[4];
            new RNGCryptoServiceProvider().GetBytes(data);
            return Convert.ToBase64String(data);
        }

        public static string HashPassword(string pass, string salt, string hashAlgorithm, string macKey)
        {
            HashAlgorithm algorithm;
            byte[] bytes = Encoding.Unicode.GetBytes(pass);
            byte[] src = Encoding.Unicode.GetBytes(salt);
            byte[] dst = new byte[src.Length + bytes.Length];
            Buffer.BlockCopy(src, 0, dst, 0, src.Length);
            Buffer.BlockCopy(bytes, 0, dst, src.Length, bytes.Length);
            if(hashAlgorithm.ToUpper().Contains("HMAC"))
            {
                if(string.IsNullOrEmpty(macKey))
                {
                    throw new ArgumentException("HMAC style hashing algorithm requires a fixed ValidationKey in the web.config or machine.config.");
                }
                KeyedHashAlgorithm algorithm2 = KeyedHashAlgorithm.Create(hashAlgorithm);
                algorithm2.Key = Encoding.ASCII.GetBytes(macKey);
                algorithm = algorithm2;
            }
            else
            {
                algorithm = HashAlgorithm.Create(hashAlgorithm);
            }
            return Convert.ToBase64String(algorithm.ComputeHash(dst));
        }
    }
}
