import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Lab05_3 {

    public byte[] sign(String data, String privateKeyContent)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privateKey = getPrivateKey(privateKeyContent);
        Signature signatureInstance = Signature.getInstance("SHA1withRSA");
        signatureInstance.initSign(privateKey);
        signatureInstance.update(data.getBytes());
        return signatureInstance.sign();
    }

    public boolean verifySignature(byte[] data, byte[] signature, String publicKeyContent)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        PublicKey publicKey = getPublicKey(publicKeyContent);
        Signature signatureInstance = Signature.getInstance("SHA1withRSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(data);
        return signatureInstance.verify(signature);
    }

    public void signAndEncrypt(String filePath, String keyUsedToEncrypt, String privateKeyPath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, SignatureException, IllegalBlockSizeException, BadPaddingException, IOException {
        String message = readFile(filePath);
        String privateKeyContent = readFile(privateKeyPath);
        byte[] signature = sign(message, privateKeyContent);
        String signatureString = Base64.getEncoder().encodeToString(signature);

        writeFile(Paths.get(filePath).getFileName().toString() + "_signature.raw", signatureString);

        byte[] encrypted = encryptWithDES(filePath, keyUsedToEncrypt);
        byte[] signatureEncrypted = encryptWithDES(Paths.get(filePath).getFileName().toString() + "_signature.raw", keyUsedToEncrypt);

        writeFile(Paths.get(filePath).getFileName().toString() + ".enc", Base64.getEncoder().encodeToString(encrypted));
        writeFile(Paths.get(filePath).getFileName().toString() + "_signature" + ".enc", Base64.getEncoder().encodeToString(signatureEncrypted));
    }

    public void decryptAndVerify(String filePath, String signFilePath, String publicKeyFilePath, String DESKeyFilePath) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, IOException {
        byte[] decryptedMessage = decryptWithDES(filePath, DESKeyFilePath);
        byte[] decryptedSignature = decryptWithDES(signFilePath, DESKeyFilePath);

        String publicKeyContent = readFile(DESKeyFilePath);
        boolean result = verifySignature(decryptedMessage, decryptedSignature, publicKeyContent);

        if (result) {
            PrintUtils.printWithColor("Success", PrintUtils.ConsoleColors.GREEN);
        }
        else {
            PrintUtils.printWithColor("Fail", PrintUtils.ConsoleColors.RED);
        }

    }

    private PrivateKey getPrivateKey(String privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String privateKeyPEM = privateKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encodedPrivateKey = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey key = keyFactory.generatePrivate(privateKeySpec);

        return key;
    }

    private PublicKey getPublicKey(String publicKeyContent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = publicKeyContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] encodedPublicKey = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }

    private String readFile(String filePath) {
        String content = "";
        try {
            content = new String(Files.readAllBytes(Paths.get(filePath)));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    private byte[] encryptWithDES(String filePath, String keyPath) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        byte[] file = Files.readAllBytes(Paths.get(filePath));
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        Key key = getDESKey(keyPath);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(file);
        return encrypted;
    }

    private byte[] decryptWithDES(String filePath, String keyPath) throws IOException {
        byte[] file = Files.readAllBytes(Paths.get(filePath));
        // decode the base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(file);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            Key key = getDESKey(keyPath);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(decodedKey);
            return decrypted;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return decodedKey;
    }

    private void writeFile(String fileName, String content) {
        try {
            Files.write(Paths.get(fileName), content.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Key getDESKey(String keyFilePath) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        String keyContent = readFile(keyFilePath);
        var ex1 = new Lab05_1();
        return ex1.getSecretKey(keyContent.getBytes());
    }

}
