public class DES {

    /**
     * Szyfruje lub deszyfruje dokładnie jeden 64-bitowy blok danych.
     */
    public static long processBlock(long block, long[] subkeys, boolean encrypt) {
        block = applyPermutation(block, DESPermutations.IP, 64);

        int L = (int) (block >>> 32);
        int R = (int) (block & 0xFFFFFFFFL);

        for (int i = 0; i < 16; i++) {
            long roundKey = subkeys[encrypt ? i : 15 - i];
            int nextL = R;
            int nextR = L ^ feistelFunction(R, roundKey);
            L = nextL;
            R = nextR;
        }

        long combined = (((long) R & 0xFFFFFFFFL) << 32) | ((long) L & 0xFFFFFFFFL);
        return applyPermutation(combined, DESPermutations.FP, 64);
    }

    private static int feistelFunction(int R, long K) {
        long expandedR = applyPermutation(Integer.toUnsignedLong(R), DESPermutations.E, 32);
        long xored = expandedR ^ K;

        int sboxOutput = 0;
        for (int i = 0; i < 8; i++) {
            int shift = 42 - (i * 6);
            int sixBits = (int) ((xored >>> shift) & 0x3F);

            int sboxVal = DESSBoxes.S_BOXES[i][sixBits];

            sboxOutput |= (sboxVal << (28 - (i * 4)));
        }

        return (int) applyPermutation(Integer.toUnsignedLong(sboxOutput), DESPermutations.P, 32);
    }

    /**
     * Generuje 16 podkluczy (po 48 bitów) z 56-bitowego klucza głównego.
     */
    public static long[] generateSubkeys(long key) {
        long[] subkeys = new long[16];
        long permutedKey = applyPermutation(key, DESPermutations.PC1, 64);

        int C = (int) (permutedKey >>> 28);
        int D = (int) (permutedKey & 0x0FFFFFFF);

        for (int i = 0; i < 16; i++) {
            C = shiftLeft28(C, DESPermutations.SHIFTS[i]);
            D = shiftLeft28(D, DESPermutations.SHIFTS[i]);

            long combined = (((long) C & 0x0FFFFFFF) << 28) | ((long) D & 0x0FFFFFFF);
            subkeys[i] = applyPermutation(combined, DESPermutations.PC2, 56);
        }
        return subkeys;
    }

    // --- Narzędzia bitowe dla DES ---

    public static long applyPermutation(long input, byte[] table, int inputSize) {
        long output = 0;
        for (int i = 0; i < table.length; i++) {
            int shiftFrom = inputSize - table[i];
            int shiftTo = table.length - 1 - i;
            long bit = (input >>> shiftFrom) & 1L;
            output |= (bit << shiftTo);
        }
        return output;
    }

    private static int shiftLeft28(int value, int shifts) {
        return ((value << shifts) | (value >>> (28 - shifts))) & 0x0FFFFFFF;
    }
}