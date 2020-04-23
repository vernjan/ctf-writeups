package cz.vernjan.ctf.he14.ch17;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class EggSafeCracker {

    public static void main(String[] args) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);

        // Crack part 1 and 4:
        System.out.println("Cracking part 1 and 4. Please wait ..");
        String part1 = null;
        String part4 = null;
        outer:
        for (int i = 0; i < 10000; i++) {
            part1 = String.format("%04d", i);
            for (int j = 0; j < 10000; j++) {
                part4 = String.format("%04d", j);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec keySpec = new SecretKeySpec((part4 + part4 + part4 + part4).getBytes(), "AES");
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                byte[] b3 = cipher.doFinal(part1.getBytes());
                String t3 = Base64.encodeBase64String(b3);
                if (t3.equals("zG+hH0zVgJvd0aaUsoUXlg==")) {
                    System.out.println("Part 4 cracked: " + part4);
                    break outer;
                }
            }
        }
        System.out.println("Part 1 cracked: " + part1);

        // Crack part 2
        String part2 = null;
        System.out.println("Cracking part 2. Please wait ..");
        for (int i = 0; i < 10000; i++) {
            part2 = String.format("%04d", i);
            byte[] b1 = part1.getBytes();
            MessageDigest digest = MessageDigest.getInstance("MD5");
            for (int j = 0; j <= i; ++j) {
                digest.update(b1);
                b1 = digest.digest(b1);
            }
            String t1 = Base64.encodeBase64String(b1);
            if (t1.equals("Q4jgwADL0QO0H7CNPMhxJw==")) {
                System.out.println("Part 2 cracked: " + part2);
                break;
            }
        }

        // Crack part 3
        System.out.println("Cracking part 3. Please wait ..");
        String part3 = null;
        for (int i = 0; i < 10000; i++) {
            part3 = String.format("%04d", i);
            MessageDigest digest = MessageDigest.getInstance("SHA1");
            byte[] b2 = part1.getBytes();
            for (int j = 0; j < i; ++j) {
                digest.update(b2);
                b2 = digest.digest(b2);
                b2[0] = 99;
                b2 = digest.digest(b2);
            }
            String t2 = Base64.encodeBase64String(b2);
            if (t2.equals("KMZ9wInjZg0C4R0EkZSjKYsonN8=")) {
                System.out.println("Part 3 cracked: " + part3);
                break;
            }
        }

        System.out.printf("The secret code is %s-%s-%s-%s\n", part1, part2, part3, part4);
    }
}
