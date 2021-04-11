//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.hackyeaster.eggcryptor;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    private static final String EGG = "V1cwd05XUXhjRkpRVkRBOQ==";

    public Crypto() {
    }

    public static byte[] decrypt(String var0, String var1) throws Exception {
        byte[] var2 = new byte[8];

        for(int var3 = 0; var3 < 8; ++var3) {
            var2[var3] = (byte)((byte)var3);
        }

        SecretKeySpec var5 = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(var0.toCharArray(), var2, 10000, 128)).getEncoded(), "AES");
        Cipher var4 = Cipher.getInstance("AES");
        var4.init(2, var5);
        return var4.doFinal(Base64.decode(var1, 0));
    }

    private static byte[] encrypt(String var0, byte[] var1) throws Exception {
        byte[] var2 = new byte[8];

        for(int var3 = 0; var3 < 8; ++var3) {
            var2[var3] = (byte)((byte)var3);
        }

        SecretKeySpec var5 = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(var0.toCharArray(), var2, 10000, 128)).getEncoded(), "AES");
        Cipher var4 = Cipher.getInstance("AES");
        var4.init(1, var5);
        return var4.doFinal(var1);
    }
}
