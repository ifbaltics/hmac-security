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

        public static unsafe byte[] ToByteArray(this SecureString secStr, Encoding encoding)
        {
            if (secStr == null)
            {
                return new byte[0];
            }

            int strLen = secStr.Length;
            int bufferSz = encoding.GetMaxByteCount(strLen);

            IntPtr bytes = IntPtr.Zero;
            IntPtr str = IntPtr.Zero;

            try
            {
                bytes = Marshal.AllocHGlobal(bufferSz);
                str = Marshal.SecureStringToBSTR(secStr);

                char* chars = (char*)str.ToPointer();
                byte* bptr = (byte*)bytes.ToPointer();
                int len = encoding.GetBytes(chars, strLen, bptr, bufferSz);

                byte[] arr = new byte[len];
                Marshal.Copy((IntPtr)bptr, arr, 0, len);

                // zero buffers
                Zero((IntPtr)chars, strLen);
                Zero((IntPtr)bptr, len);

                return arr;
            }
            finally
            {
                if (str != IntPtr.Zero) Marshal.ZeroFreeBSTR(str);
                if (bytes != IntPtr.Zero) Marshal.FreeHGlobal(bytes);
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