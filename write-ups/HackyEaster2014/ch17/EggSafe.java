//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package ps.hacking.hackyeaster.eggsafe;

import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.awt.image.ImageObserver;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.JFrame;
import javax.swing.JPanel;
import org.apache.commons.codec.binary.Base64;

public class EggSafe {
    private static String PATTERN = "([0-9]{4}-){3}[0-9]{4}";
    private static byte[] SALT = new byte[]{4, 115, 33, -116, 126, -56, -114, -103};
    private static final byte[] iv = new byte[16];
    private static final IvParameterSpec ips;
    private static final String f = "1453-9373-4587-8030";

    static {
        ips = new IvParameterSpec(iv);
    }

    public EggSafe() {
    }

    public static void main(String[] args) {
        try {
            if (args != null && args.length == 1 && args[0].matches(PATTERN)) {
                String[] parts = args[0].split("-");
                byte[] b0 = parts[0].getBytes();
                MessageDigest digest = MessageDigest.getInstance("MD5");
                byte[] b1 = parts[0].getBytes();

                for(int i = 0; i <= Integer.parseInt(parts[1]); ++i) {
                    digest.update(b1);
                    b1 = digest.digest(b1);
                }

                digest = MessageDigest.getInstance("SHA1");
                byte[] b2 = parts[0].getBytes();

                for(int i = 0; i < Integer.parseInt(parts[2]); ++i) {
                    digest.update(b2);
                    b2 = digest.digest(b2);
                    b2[0] = 99;
                    b2 = digest.digest(b2);
                }

                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec k = new SecretKeySpec((parts[3] + parts[3] + parts[3] + parts[3]).getBytes(), "AES");
                c.init(1, k, ips);
                byte[] b3 = c.doFinal(b0);
                String t1 = Base64.encodeBase64String(b1);
                String t2 = Base64.encodeBase64String(b2);
                String t3 = Base64.encodeBase64String(b3);
                if (t1.equals("Q4jgwADL0QO0H7CNPMhxJw==") && t2.equals("KMZ9wInjZg0C4R0EkZSjKYsonN8=") && t3.equals("zG+hH0zVgJvd0aaUsoUXlg==")) {
                    yes(args[0]);
                } else {
                    nope();
                }
            } else {
                nope();
            }
        } catch (Exception var12) {
            var12.printStackTrace();
        }

    }

    public static void yes(String pass) throws Exception {
        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(3);
        frame.setSize(500, 500);
        byte[] imageData = decrypt(pass, "1.png");
        final BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageData));
        JPanel p = new JPanel() {
            private static final long serialVersionUID = 1L;

            protected void paintComponent(Graphics g) {
                g.drawImage(image, 0, 0, (ImageObserver)null);
            }
        };
        frame.add(p);
        frame.setVisible(true);
    }

    public static void nope() throws Exception {
        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(3);
        frame.setSize(316, 330);
        byte[] imageData = decrypt("7874-1095-2006-1650", "2.png");
        final BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageData));
        JPanel p = new JPanel() {
            private static final long serialVersionUID = 1L;

            protected void paintComponent(Graphics g) {
                g.drawImage(image, 0, 0, (ImageObserver)null);
            }
        };
        frame.add(p);
        frame.setVisible(true);
    }

    private static byte[] decrypt(String pass, String file) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(file));
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(pass.toCharArray(), SALT, 65536, 128);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(2, secret, ips);
        return cipher.doFinal(data);
    }
}
