import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class Lab05_2 {
    private static final Scanner scanner = new Scanner(System.in);

    private static class TypeSelectionChoice {
        static final int DECRYPT = 1;
        static final int ENCRYPT = 2;
        static final int EXIT = 3;
    }    

    private static int RSA_KEY_SIZE = 2048;
    
    public static void main(String[] args) throws Exception {
        var program = new Lab05_2();
        PrintUtils.printWithColor("------- Hello, welcome to Lab 05 Part 2 - RSA -------", PrintUtils.ConsoleColors.GREEN);
        while (true) {
            try {
                program.main();
            } catch (Exception e) {
                PrintUtils.printWithColor("An error occurred!", PrintUtils.ConsoleColors.RED);
                e.printStackTrace();
            }
        }
    }

    private void main() throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InterruptedException {
        int type = typeSelection();

        if (type == TypeSelectionChoice.EXIT) {
            System.exit(0);
        }
        String keyPath = "";
        if (type == TypeSelectionChoice.ENCRYPT) {
            keyPath = fileToProcessPathInput("Please enter the public key file name: ");
        } else if (type == TypeSelectionChoice.DECRYPT) {
            keyPath = fileToProcessPathInput("Please enter the private key file name: ");
        }

        String filePath = fileToProcessPathInput("Please enter the file path to process: ");

        doRSAAction(type, keyPath, filePath);
        
    }

    private void doRSAAction(int type, String keyPath, String filePath) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, IOException, InterruptedException {
        long startTime = System.currentTimeMillis();
        Cipher cipher = Cipher.getInstance("RSA");
        Key key;
        String keyContent = getFileContent(keyPath);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // String content= getFileContent(filePath);
        switch (type) {
            case TypeSelectionChoice.ENCRYPT:
                String publicKeyPEM = keyContent
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");
                byte[] encodedPublicKey = Base64.getDecoder().decode(publicKeyPEM);
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
                key = keyFactory.generatePublic(publicKeySpec);
                cipher.init(Cipher.ENCRYPT_MODE, key);
                break;
            case TypeSelectionChoice.DECRYPT:
            String privateKeyPEM = keyContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
                byte[] encodedPrivateKey = Base64.getDecoder().decode(privateKeyPEM);
                
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
                key = keyFactory.generatePrivate(privateKeySpec);
                cipher.init(Cipher.DECRYPT_MODE, key);
                break;
        }

        try (FileChannel fc = new FileInputStream(filePath).getChannel()) {
            /*
             * If encrypting (type == TypeSelectionChoice.ENCRYPT), the chunk size is (RSA_KEY_SIZE / 8) - 11. This is because RSA encryption with PKCS#1 padding can only handle data up to the size of the key modulus minus the overhead for the padding scheme. For a 2048-bit key, this is 256 bytes for the key, minus approximately 11 bytes for the padding, leaving 245 bytes.
             */
            /*
             * If decrypting, the chunk size is RSA_KEY_SIZE / 8. This is because the encrypted data will be exactly the size of the key modulus, which is RSA_KEY_SIZE / 8 bytes for a 2048-bit key.
             */
            final int MAP_SIZE = type == TypeSelectionChoice.ENCRYPT ? (RSA_KEY_SIZE / 8) - 11 : RSA_KEY_SIZE / 8;           
            long fileSize = fc.size();
            long position = 0;
            long lineNum = 0;

            while (position < fileSize) {
                long remaining = fileSize - position;
                int bytesNumberToMap = (int) Math.min(MAP_SIZE, remaining);
                MappedByteBuffer bb = fc.map(FileChannel.MapMode.READ_ONLY, position, bytesNumberToMap);
                byte[] bytes = new byte[bytesNumberToMap];
                bb.get(bytes);
                final long finalLineNum = lineNum;
                byte[]result = cipher.doFinal(bytes);
                dumpOutputToFile(type, result, finalLineNum == 0);
                position += bytesNumberToMap;
                lineNum++;
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        long endTime = System.currentTimeMillis();
        PrintUtils.printTimePassed(startTime, endTime);
    }

    private String fileToProcessPathInput(String promptMessage) {
        boolean valid = false;

        while (!valid) {
            try {
                PrintUtils.printInlineWithColor(promptMessage, PrintUtils.ConsoleColors.GREEN);
                String filePath = scanner.nextLine();
                valid = validateFilePath(filePath);
                if (valid) {
                    return filePath;
                }
                else {
                    PrintUtils.printWithColor("File does not exist! Please try again.", PrintUtils.ConsoleColors.YELLOW_BRIGHT);
                }
            } catch (Exception e) {
                PrintUtils.printWithColor("Invalid Choice! Please choose again.",
                        PrintUtils.ConsoleColors.YELLOW_BRIGHT);
                ;
                scanner.nextLine();
            }
        }

        return "";
    }

    public int typeSelection() {
        System.out.println("Please choose an option:");
        System.out.println("1. Decrypt");
        System.out.println("2. Encrypt");
        System.out.println("3. Exit");
        boolean valid = false;
        try {
            while (!valid) {
                try {
                    PrintUtils.printInlineWithColor("Please type a number: ", PrintUtils.ConsoleColors.GREEN);
                    int choice = scanner.nextInt();
                    valid = validateTypeSelection(choice);
                    if (scanner.hasNextLine()) {
                        scanner.nextLine();
                    }
                    if (valid) {
                        return choice;
                    }
                } catch (Exception e) {
                    PrintUtils.printWithColor("Invalid Choice! Please choose again.",
                            PrintUtils.ConsoleColors.YELLOW_BRIGHT);
                    ;
                    scanner.nextLine();
                }
            }
        } finally {
        }
        return -1;
    }


    /**
     * @description validate if file exists
     * @param filePath file path to validate
     * @return true if the file exists, false otherwise
     */
    private boolean validateFilePath(String filePath) {
        File file = new File(filePath);
        return file.exists();
    }

    private boolean validateTypeSelection(int choice) {
        boolean validChoice = false;
        List<Integer> validTypeSelectionChoice = new ArrayList<Integer>();
        validTypeSelectionChoice.add(TypeSelectionChoice.DECRYPT);
        validTypeSelectionChoice.add(TypeSelectionChoice.ENCRYPT);
        validTypeSelectionChoice.add(TypeSelectionChoice.EXIT);
        if (validTypeSelectionChoice.contains(choice)) {
            validChoice = true;
        }
        return validChoice;
    }

    private String getOuptputFileName(int type) {
        String outputFileName = UUID.randomUUID().toString();
        switch (type) {
            case TypeSelectionChoice.DECRYPT:
                outputFileName = "rsa-output.dec";
                break;
            case TypeSelectionChoice.ENCRYPT:
                outputFileName = "rsa-output.enc";
                break;
        }
        return outputFileName;
    }

    private void dumpOutputToFile(int type, byte[] bytes, boolean fistTimeDumping)
            throws IOException, InterruptedException {
        String outputFileName = getOuptputFileName(type);

        File outputFile = new File(outputFileName);
        // create file if not exists
        if (fistTimeDumping) {
            if (!outputFile.exists()) {
                outputFile.createNewFile();
            } else {
                outputFile.delete();
                outputFile.createNewFile();
            }
        } else {
            if (!outputFile.exists()) {
                outputFile.createNewFile();
            }
        }

        try (FileOutputStream fos = new FileOutputStream(outputFileName, !fistTimeDumping)) {
            fos.write(bytes);
        }
    }

    private String getFileContent(String filePath) {
        File file = new File(filePath);
        if (!file.exists()) {
            PrintUtils.printWithColor("File does not exist!", PrintUtils.ConsoleColors.RED);
            return null;
        }
        byte[] fileContent = null;
        try (FileInputStream fis = new FileInputStream(filePath);) {
            byte[] bytes = new byte[(int) file.length()];
            fis.read(bytes);
            fileContent = bytes;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new String(fileContent, StandardCharsets.UTF_8);
    }


}
