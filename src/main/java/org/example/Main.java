package org.example;

import javax.crypto.SecretKey;

public class Main {
    public static void main(String[] args) {
       try {
           SecretKey secretKey = EncryptionUtil.generateKey();
           String originalData = "Hello World!";
           byte[] encryptedData = EncryptionUtil.encrypt(originalData, secretKey);
           System.out.println("Original data: " + originalData);
           System.out.println("Encrypted data: " + encryptedData);
           String decryptedData = EncryptionUtil.decrypt(encryptedData, secretKey);
           System.out.println("Decrypted data: " + decryptedData);

       } catch (Exception e) {
           e.printStackTrace();
       }
    }
}