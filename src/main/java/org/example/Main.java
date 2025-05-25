package org.example;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) {
       try {

           /*
           Using simple AES encryption/decryption
            */
           SecretKey secretKey = EncryptionUtil.generateKey();
           String originalData = "Hello World!";
           byte[] encryptedData = EncryptionUtil.encrypt(originalData, secretKey);
           System.out.println("Original data: " + originalData);
           System.out.println("Encrypted data: " + encryptedData);
           String decryptedData = EncryptionUtil.decrypt(encryptedData, secretKey);
           System.out.println("Decrypted data: " + decryptedData);

           /*
           Using SHA-256 encryption
            */
           String password = "password";
           String hashedPassword = EncryptionUtil.hash(password);
           System.out.println("Hashed password: " + hashedPassword);

       } catch (NoSuchAlgorithmException e) {
           System.err.println("Algorithm not found: " + e.getMessage());
       } catch (InvalidKeyException e) {
           System.err.println("Invalid key: " + e.getMessage());
       } catch (Exception e) {
           e.printStackTrace();
       }
    }
}