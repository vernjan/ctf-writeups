package cz.vernjan.ctf.he21;

import cz.vernjan.ctf.Resources;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Eggcryptor {

    private static final String alphanum = "abcdefghijklmnopqrstuvwxyz";

    private static final byte[] PNG_MAGIC_HEADER = {(byte) 0x89, 0x50, 0x4E, 0x47};
    private static byte[] IV = new byte[8];

    static {
        for (int i = 0; i < 8; ++i) {
            IV[i] = (byte) i;
        }
    }
//    private static final byte[] PNG_MAGIC_HEADER = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

    public static void main(String[] args) throws Exception {
        byte[] data = Base64.getDecoder().decode(
                Resources.INSTANCE.asString("he21/eggcryptor.raw"));

        for (char ch : "yz".toCharArray()) {
            System.out.println("Ch: " + ch);
            for (int i = 0; i < 10_000; i++) {
                String pin = ch + String.format("%04d", i);
                try {
                    byte[] header = Arrays.copyOf(decrypt(pin, data), 4);
                    if (Arrays.equals(PNG_MAGIC_HEADER, header)) {
                        System.out.println("Bingo! Pin is " + pin);
                        System.exit(0);
                    }
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    public static byte[] decrypt(String pin, byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                        .generateSecret(new PBEKeySpec(pin.toCharArray(), IV, 10000, 128))
                        .getEncoded(), "AES");

        Cipher aes = Cipher.getInstance("AES");
        aes.init(Cipher.DECRYPT_MODE, key);
        return aes.doFinal(data);
    }

}
