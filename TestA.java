package com.test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by adu on 2017/5/23.
 */
public class TestA {
    private static final int BUFFER_SIZE = 4096;
    private static final int FILE_KEY_SIZE = 128;
    private static final String KEY_DIR = "C:\\Users\\adu\\e";
    public static void encryptAES(SecretKey key, File file) {
        byte[] encrypted = null;
        try {
//            Key skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            byte[] iv = new byte[cipher.getBlockSize()];

            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
            FileInputStream fis = new FileInputStream(file);
            FileOutputStream fos = new FileOutputStream(new File(file.getParent(), file.getName() + ".m"));
            int len = 0;
            byte[] buffer = new byte[1024];
            do {
                len = fis.read(buffer);
                encrypted = cipher.doFinal(buffer, 0, len);
                fos.write(encrypted);
            } while (len > 0);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void encryptAES(File file) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey aesKey = kgen.generateKey();
        // Encrypt cipher
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(aesKey.getEncoded());
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);

        File outFile = new File(file.getParent(), file.getName() + ".e");

        // Encrypt
        try (
                FileInputStream fis = new FileInputStream(file);
                CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(outFile), encryptCipher)
        ) {
            copy(fis, cipherOutputStream, -1);
        }

        try (FileOutputStream fos = new FileOutputStream(outFile, true)){
            byte[] encryptKey = RSAUtil.encrypt(RSAUtil.loadPublicKeyByStr(RSAUtil.loadPublicKeyByFile(KEY_DIR)), aesKey.getEncoded());
            if (encryptKey.length != FILE_KEY_SIZE) {
                throw new RuntimeException("key size error!");
            }
            fos.write(encryptKey);
        }
    }

    private static Key readKeyFromFile(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.skip(file.length() - FILE_KEY_SIZE);
            byte[] encryptKeyByte = new byte[FILE_KEY_SIZE];
            fis.read(encryptKeyByte);
            byte[] keyByte = RSAUtil.decrypt(RSAUtil.loadPrivateKeyByStr(RSAUtil.loadPrivateKeyByFile(KEY_DIR)), encryptKeyByte);
            Key aesKey = new SecretKeySpec(keyByte, "AES");
            return aesKey;
        }
    }

    public static void decryptFile(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file);
        FileOutputStream dFos = new FileOutputStream(new File(file.getParent(), file.getName() + ".d"))) {
            Key aesKey = readKeyFromFile(file);

            File tmpFile = new File(file.getParent(), file.getName() + ".t");
            FileOutputStream tmpFos = new FileOutputStream(tmpFile);
            copy(fis, tmpFos, file.length() - FILE_KEY_SIZE);
            tmpFos.flush();
            tmpFos.close();

            FileInputStream eFis = new FileInputStream(tmpFile);

            Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(aesKey.getEncoded());
            decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);

            CipherInputStream cipherInputStream = new CipherInputStream(eFis, decryptCipher);
            copy(cipherInputStream, dFos, -1);
            cipherInputStream.close();
            eFis.close();
            tmpFile.delete();
        }
    }

    public static void copy(InputStream in, OutputStream out, long len) throws IOException {
        long byteCount = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead = -1;
        while ((bytesRead = in.read(buffer)) != -1) {
            if (len > 0 && byteCount + bytesRead > len) {
                out.write(buffer, 0, (int) (len - byteCount));
                break;
            }
            out.write(buffer, 0, bytesRead);
            byteCount += bytesRead;
        }
        out.flush();
    }

    private static void printHex(byte[] content) {
        for (byte b : content) {
            System.out.print(" 0x" + Integer.toHexString(b));
        }
        System.out.println();
    }

    public static String base64(byte[] content) {
        return Base64.getEncoder().encodeToString(content);
    }

    public static void testEncrypt() {
        try {
            String s = "Hello there. How are you? Have a nice day.";

            // Generate key
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey aesKey = kgen.generateKey();

            // Encrypt cipher
            Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(aesKey.getEncoded());
            encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivParameterSpec);

            // Encrypt
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
            cipherOutputStream.write(s.getBytes());
            cipherOutputStream.flush();
            cipherOutputStream.close();
            byte[] encryptedBytes = outputStream.toByteArray();

            // Decrypt cipher
            Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            IvParameterSpec ivParameterSpec = new IvParameterSpec(aesKey.getEncoded());
            decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);

            // Decrypt
            outputStream = new ByteArrayOutputStream();
            ByteArrayInputStream inStream = new ByteArrayInputStream(encryptedBytes);
            CipherInputStream cipherInputStream = new CipherInputStream(inStream, decryptCipher);
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = cipherInputStream.read(buf)) >= 0) {
                outputStream.write(buf, 0, bytesRead);
            }

            System.out.println("Result: " + new String(outputStream.toByteArray()));

        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String args[]) throws Exception {
//        ByteArrayOutputStream bos = new ByteArrayOutputStream();
//        byte[] test = new byte[]{1,2,3,4,5,6,7,8};
//        copy(new ByteArrayInputStream(test), bos, 3);
//        byte[] resul = bos.toByteArray();
        encryptAES(new File("d:\\bak\\bak.rar"));
        decryptFile(new File("d:\\bak\\bak.rar.e"));
//        testEncrypt();
//        KeyGenerator kgen = KeyGenerator.getInstance("AES");
//        kgen.init(256);
//        SecretKey aesKey = kgen.generateKey();

//        System.err.println(aesKey.getAlgorithm() + "" + aesKey.getEncoded().length);
//    File file = new File("D:\\bak\\bak.rar");
//        encryptAES(aesKey.getEncoded(, file);
//    encryptAES("123123123", file);
    }
}
