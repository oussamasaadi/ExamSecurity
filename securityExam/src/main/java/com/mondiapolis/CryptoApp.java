package com.mondiapolis;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class CryptoApp {

    private static final String CERTIFICATE_FILE = "certificate.cert";
    private static final String KEYSTORE_FILE = "examen.jks";
    private static final String KEYSTORE_PASSWORD = "123456";
    private static final String KEY_ALIAS = "examen";



    public static String cryptwithRSA() throws Exception {
        PublicKey publicKey = getPublicKeyFromCertificate(CERTIFICATE_FILE);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedMessage = cipher.doFinal("Bonjour 3A LIA".getBytes());
        String encodedMessage = encodeBase64(encryptedMessage);
        return encodedMessage;
    }

    public static String decryptwithRSA(String CryptedEncodedMsg) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromKeyStore(KEYSTORE_FILE, KEYSTORE_PASSWORD, KEY_ALIAS);
        byte[] decodedMessage = decodeBase64(CryptedEncodedMsg);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(decodedMessage);
        return new String(decryptedMessage);
    }

    public static String cryptwithAES() throws Exception {
        String message="Message Clair";
        String msgsecret = "QWERTYUIIUYTREWQ";
        SecretKey secretKey = new SecretKeySpec(msgsecret.getBytes(),0,msgsecret.length(),"AES");
        byte[] codkey=secretKey.getEncoded();
        System.out.println(Base64.getEncoder().encodeToString(codkey));
        Cipher cipher =Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptMsg=cipher.doFinal(message.getBytes());
        String encodeEncryptMsg= Base64.getEncoder().encodeToString(encryptMsg);
        return encodeEncryptMsg;
    }


    public static String decryptwithAES(String CryptedEncodedMsg) throws Exception {
        byte[] decodedMsg = Base64.getDecoder().decode(CryptedEncodedMsg);
        String msgsecret = "QWERTYUIIUYTREWQ";
        SecretKey secretKey = new SecretKeySpec(msgsecret.getBytes(),0,msgsecret.length(),"AES");
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] decryptedMsg =cipher.doFinal(decodedMsg);
        return new String(decryptedMsg);
    }


    public static PublicKey getPublicKeyFromCertificate(String fileName) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        return certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyStore(String fileName, String password, String alias) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, password.toCharArray());
        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

    public static SecretKey getSecretKeyFromKeyStore(String fileName, String password, String alias) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, password.toCharArray());
        return (SecretKey) keyStore.getKey(alias, password.toCharArray());
    }

    public static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] decodeBase64(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }
}
