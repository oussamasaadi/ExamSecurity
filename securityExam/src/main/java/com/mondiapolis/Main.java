package com.mondiapolis;

import static com.mondiapolis.CryptoApp.*;

public class Main {
    public static void main(String[] args) {
        try {
            System.out.println("RSA encryption:");
            String encryptedRSA = cryptwithRSA();
            System.out.println("Encrypted message: " + encryptedRSA);
            String decryptedRSA = decryptwithRSA(encryptedRSA);
            System.out.println("Decrypted message: " + decryptedRSA);

            System.out.println("AES encryption:");
            String encryptedAES = cryptwithAES();
            System.out.println("Encrypted message: " + encryptedAES);
            String decryptedAES = decryptwithAES(encryptedAES);
            System.out.println("Decrypted message: " + decryptedAES);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

