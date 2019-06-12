namespace Security.HMAC
{
    public static class MemTools
    {
        public static unsafe bool Equals(byte* b0, byte* b1, int length)
        {
            byte* lastAddr = b0 + length;
            byte* lastAddrMinus32 = lastAddr - 32;
            while (b0 < lastAddrMinus32) // unroll the loop so that we are comparing 32 bytes at a time.
            {
                if (*(ulong*)b0 != *(ulong*)b1) return false;
                if (*(ulong*)(b0 + 8) != *(ulong*)(b1 + 8)) return false;
                if (*(ulong*)(b0 + 16) != *(ulong*)(b1 + 16)) return false;
                if (*(ulong*)(b0 + 24) != *(ulong*)(b1 + 24)) return false;
                b0 += 32;
                b1 += 32;
            }

            while (b0 < lastAddr)
            {
                if (*b0 != *b1) return false;
                b0++;
                b1++;
            }

            return true;
        }

        public static unsafe bool Equals(byte[] arr0, byte[] arr1)
        {
            if (arr0.Length != arr1.Length) return false;

            fixed (byte* b0 = arr0)
            fixed (byte* b1 = arr1)
            {
                return Equals(b0, b1, arr0.Length);
            }
        }
    }
}