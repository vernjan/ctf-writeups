package cz.vernjan.ctf.he21;

import com.google.common.hash.Hashing;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class CafeShop {

    public static void main(String[] args) {

        String productName = "Vanilla Cafe";
        String id = "11865457";

        String sha256hex = Hashing.sha256()
                .hashString(productName, StandardCharsets.UTF_8)
                .toString();

        System.out.println(sha256hex);

        System.out.println(new BigInteger(sha256hex, 16));

        System.out.println(Hashing.sha256()
                .hashString(productName, StandardCharsets.UTF_8).asInt());

    }

}
