import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class DESX {

    public static byte[] process(byte[] data, byte[] key, boolean encrypt) throws Exception {
        if (key.length != 24) throw new Exception("Klucz musi mieć dokładnie 24 bajty.");

        // Podział klucza na K1, K2 i K3
        long k1 = bytesToLong(Arrays.copyOfRange(key, 0, 8));
        long k2 = bytesToLong(Arrays.copyOfRange(key, 8, 16));
        long k3 = bytesToLong(Arrays.copyOfRange(key, 16, 24));

        // Zlecenie wygenerowania podkluczy do rdzenia DES (używając K2)
        long[] subkeys = DES.generateSubkeys(k2);

        byte[] inputData = encrypt ? addPKCS5Padding(data) : data;
        if (inputData.length % 8 != 0) throw new Exception("Błąd długości danych.");

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] blockBytes = new byte[8];

        // Pętla tnąca wiadomość na bloki po 8 bajtów (64 bity)
        for (int i = 0; i < inputData.length; i += 8) {
            System.arraycopy(inputData, i, blockBytes, 0, 8);
            long block = bytesToLong(blockBytes);

            if (encrypt) {
                block ^= k1; // Pre-whitening (DESX)
                block = DES.processBlock(block, subkeys, true); // Rdzeń DES
                block ^= k3; // Post-whitening (DESX)
            } else {
                block ^= k3; // Odwrócenie post-whitening
                block = DES.processBlock(block, subkeys, false); // Odwrócenie DES
                block ^= k1; // Odwrócenie pre-whitening
            }

            outputStream.write(longToBytes(block));
        }

        byte[] result = outputStream.toByteArray();
        return encrypt ? result : removePKCS5Padding(result);
    }

    // --- Narzędzia pomocnicze (Padding i konwersje bajtów) ---

    private static byte[] addPKCS5Padding(byte[] data) {
        int paddingLength = 8 - (data.length % 8);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) paddingLength;
        }
        return paddedData;
    }

    private static byte[] removePKCS5Padding(byte[] data) throws Exception {
        if (data.length == 0 || data.length % 8 != 0) throw new Exception("Nieprawidłowy rozmiar danych.");
        int paddingLength = data[data.length - 1];
        if (paddingLength < 1 || paddingLength > 8) throw new Exception("Błąd dopełnienia (paddingu).");
        byte[] unpaddedData = new byte[data.length - paddingLength];
        System.arraycopy(data, 0, unpaddedData, 0, unpaddedData.length);
        return unpaddedData;
    }

    private static long bytesToLong(byte[] b) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result <<= 8;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

    private static byte[] longToBytes(long l) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (l & 0xFF);
            l >>= 8;
        }
        return result;
    }
}