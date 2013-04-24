#region License

/*
Illusory Studios C# Crypto Library (CryptSharp)
Copyright (c) 2010 James F. Bellinger <jfb@zer7.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#endregion

namespace CryptSharpSQL
{
    using System;
    using System.Security.Cryptography;
    using System.Globalization;
    using System.Text.RegularExpressions;
    using Utility;


    public class CrypterSQL
    {
        static readonly int MaxKeyLength = 72;
        static readonly int MinKeyLength = 0;

		public static string GenerateSalt(int rounds)
		{
			Helper.CheckRange("rounds", rounds, 4, 31);
			return string.Format("$2a${0}${1}", rounds.ToString("00"),
								 new string(UnixBase64.Encode(GenerateSaltBytes(16))));
		}

        protected static byte[] GenerateSaltBytes(int saltLength)
        {
            Helper.CheckRange("saltLength", saltLength, 0, int.MaxValue);
            var rng = new RNGCryptoServiceProvider();
            var salt = new byte[saltLength];
            rng.GetBytes(salt);
            return salt;
        }

        public byte[] PadKeyForCrypt(byte[] key, out bool padded)
        {
            Helper.CheckNull("key", key);
            int newLength = Math.Min(MaxKeyLength, Math.Max(MinKeyLength, key.Length));
            padded = newLength != key.Length;
            if (padded)
            {
                Array.Resize(ref key, newLength);
            }
            return key;
        }

        public string PadKeyThenCrypt(byte[] key)
        {
            return PadKeyThenCrypt(key, GenerateSalt(6));
        }

        public string PadKeyThenCrypt(byte[] key, string salt)
        {
            bool padded;
            byte[] newKey = PadKeyForCrypt(key, out padded);
            string result = Crypt(newKey, salt);
            if (padded)
            {
                Array.Clear(newKey, 0, newKey.Length);
            }
            return result;
        }

        protected static void CheckKey(byte[] key)
        {
            Helper.CheckRange("key", key, MinKeyLength, MaxKeyLength);
        }

        private static readonly Regex _regex;

        static CrypterSQL()
		{
			_regex = new Regex(@"\A" + Regex + @"\z");
		}

        public static string Regex
		{
			get
			{
				return @"\$2a\$([0-9]{2})\$([A-Za-z0-9./]{22})([A-Za-z0-9./]{"
					   + ((BlowfishCipher.BCryptLength * 8 + 5) / 6).ToString(CultureInfo.InvariantCulture) + @"})?";
			}
		}	

		public static string Crypt(byte[] key, string salt)
		{
			CheckKey(key);
			Helper.CheckNull("salt", salt);

			Match saltMatch = _regex.Match(salt);
			if (!saltMatch.Success)
			{
				throw new ArgumentException("Invalid salt.", "salt");
			}

			int rounds = int.Parse(saltMatch.Groups[1].Value);
			if (rounds < 4 || rounds > 31)
			{
				throw new ArgumentException("Invalid number of rounds.", "salt");
			}
			byte[] saltBytes = UnixBase64.Decode(saltMatch.Groups[2].Value, 128);

			bool resized = key.Length < MaxKeyLength;

			if (resized)
			{
				Array.Resize(ref key, key.Length + 1);
			} // The ending null terminator is vital for compatibility

			byte[] crypt = BlowfishCipher.BCrypt(key, saltBytes, rounds);

			string result = string.Format("$2a${0}${1}{2}", rounds.ToString("00"),
										  new string(UnixBase64.Encode(saltBytes)),
										  new string(UnixBase64.Encode(crypt)));

			Array.Clear(crypt, 0, crypt.Length);
			Array.Clear(saltBytes, 0, saltBytes.Length);

			if (resized)
			{
				Array.Clear(key, 0, key.Length);
			} // This is new since we resized it.
			return result;
		}

    }
}
