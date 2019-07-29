namespace Security.HMAC
{
    using System;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;

    public static class SecureStringExtensions
    {
        public static SecureString FromByteArray(this byte[] bytes, Encoding encoding)
        {
            if (bytes == null)
            {
                return null;
            }

            return encoding
                .GetChars(bytes)
                .Aggregate(new SecureString(), AppendChar, MakeReadOnly);
        }

        public static byte[] ToByteArray(this SecureString secStr, Encoding encoding)
        {
            if (secStr == null || secStr.Length == 0)
            {
                return new byte[0];
            }

            IntPtr ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.SecureStringToGlobalAllocUnicode(secStr);
                var result = Marshal.PtrToStringUni(ptr);
                if (result == null)
                    throw new Exception("Failed to retrieve security string.");

                return encoding.GetBytes(result);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(ptr);
                }
            }
        }

        public static SecureString ToSecureString(this string str) => str?.Aggregate(new SecureString(), AppendChar, MakeReadOnly);

        private static SecureString AppendChar(SecureString ss, char c)
        {
            ss.AppendChar(c);
            return ss;
        }

        private static SecureString MakeReadOnly(SecureString ss)
        {
            ss.MakeReadOnly();
            return ss;
        }

        private static void Zero(IntPtr ptr, int len)
        {
            for (int i = 0; i < len; i++)
            {
                Marshal.WriteByte(ptr, i, 0);
            }
        }
    }
}