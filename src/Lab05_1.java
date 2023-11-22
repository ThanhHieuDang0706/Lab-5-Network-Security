import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.InputMismatchException;



/**
 * This class represents Lab05_1, which is a program for network security.
 * It provides functionality for encryption and decryption using different modes and algorithms.
 * The program prompts the user to choose the type of program (encryption or decryption),
 * the mode of operation, and the file to process.
 * It also validates user inputs and checks if the file exists.
 */
public class Lab05_1 {
    /**
     * This class represents the available choices for type selection.
     * It contains constants representing the choices to decode, encode, or exit.
     */
    private static class TypeSelectionChoice {
        static final int DECRYPT = 1;
        static final int ENCRYPT = 2;
        static final int EXIT = 3;
    }


    private static final Scanner scanner = new Scanner(System.in);
    /**
     * This class represents the mode selection options for encryption.
     * It provides constants for different encryption modes.
     */
    private static class ModeSelection {
        static final int DES_ECB_PKCS5_PADDING = 1;
        static final int DES_ECB_NO_PADDING = 2;
        static final int DES_CBC_PKCS5_PADDING = 3;
        static final int DES_CBC_NO_PADDING = 4;
        static final int EXIT = 5;
    }

    public static void main(String[] args) throws Exception {
        var lab05_1 = new Lab05_1();
        PrintUtils.printWithColor("------- Hello, welcome to Lab 05 Part 1 -------", PrintUtils.ConsoleColors.GREEN);
        PrintUtils.printWithColor("------- Please choose a type of program -------", PrintUtils.ConsoleColors.GREEN);
        while (true) {
            try {
                lab05_1.main();
            }
            catch (Exception e) {
                PrintUtils.printWithColor("An error occurred!", PrintUtils.ConsoleColors.RED);
                e.printStackTrace();
            }
        }
    }

    /**
     * The main method of the Lab05_1 class.
     * This method is the entry point of the program.
     * It prompts the user to choose a type of program and performs the corresponding actions based on the user's choice.
     * If the user chooses to exit the program, it terminates the program.
     * If the user chooses to encode or decode, it prompts the user to choose a mode and performs the corresponding actions based on the user's choice.
     * It also prompts the user to enter the name of the file to process and the name of the key file.
     * @throws Exception if an error occurs during the execution of the program.
     */
    public void main() throws Exception {
        int choice = typeSelection();
        if (choice == TypeSelectionChoice.EXIT) {
            PrintUtils.printWithColor("Exiting program...", PrintUtils.ConsoleColors.RED);
            System.exit(0);
        }

        int modeChoice = -1;
        if (choice == TypeSelectionChoice.DECRYPT || choice == TypeSelectionChoice.ENCRYPT) {
            modeChoice = modeSelection();
        }


        if (modeChoice == ModeSelection.EXIT) {
            PrintUtils.printWithColor("Exiting program...", PrintUtils.ConsoleColors.RED);
            System.exit(0);
        }

        String fileToProcessPathInput = fileToProcessPathInput();
        String keyFileName = keyFileNameInput();

        doActionDES(choice, modeChoice, keyFileName, fileToProcessPathInput);
    }

    private int modeSelection() {
        PrintUtils.printWithColor("------- Please select a mode --------", PrintUtils.ConsoleColors.GREEN);
        PrintUtils.print("1. DES/ECB/PKCS5Padding");
        PrintUtils.print("2. DES/ECB/NoPadding");
        PrintUtils.print("3. DES/CBC/PKCS5Padding");
        PrintUtils.print("4. DES/CBC/NoPadding");
        PrintUtils.print("5. Exit");

        boolean valid = false;
        try {
            while (!valid) {
                try {
                    System.out.print("Please type a number: ");
                    int choice;
                    if (scanner.hasNextInt()) {
                        choice = scanner.nextInt();
                        scanner.nextLine();
                        valid = validateModeSelection(choice);
                        if (valid) {
                            return choice;
                        }
                    } else {
                        PrintUtils.printWithColor("Invalid Choice! Please choose again.", PrintUtils.ConsoleColors.YELLOW_BRIGHT);;
                        if (scanner.hasNext()) {
                            scanner.nextLine();
                        }
                    }
                    
                } catch (InputMismatchException e) {
                    PrintUtils.printWithColor("Invalid Choice! Please choose again.", PrintUtils.ConsoleColors.YELLOW_BRIGHT);;
                    if (scanner.hasNextLine()) {
                        scanner.nextLine();
                    }
                }
            }
        }
        finally {}
        return -1;
    }

    public int typeSelection() {
        System.out.println("1. Decrypt");
        System.out.println("2. Encrypt");
        System.out.println("3. Exit");
        boolean valid = false;
        try {
            while (!valid) {
                try {
                    System.out.print("Please type a number: ");
                    int choice = scanner.nextInt();
                    valid = validateTypeSelection(choice);
                    if (valid) {
                        return choice;
                    }
                }
                catch(Exception e) {
                    PrintUtils.printWithColor("Invalid Choice! Please choose again.", PrintUtils.ConsoleColors.YELLOW_BRIGHT);;
                    scanner.nextLine();
                }
            }
        }
        finally {
        }
        return -1;
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

    private IvParameterSpec getIvSpecForCBCCipher(int type, int mode, String key) {
        return getIvSpecForCBCCipher(type, mode, key, "");
    }

    private IvParameterSpec getIvSpecForCBCCipher(int type, int mode, String key, String content) {
        if (type == TypeSelectionChoice.ENCRYPT) {
            byte[] iv = new byte[8]; // 8 bytes for DES
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            return ivspec;
        }
        if (type == TypeSelectionChoice.DECRYPT) {
            byte[] data = content.getBytes();
            byte[] ivBase64 = Arrays.copyOfRange(data, 0, 12);
            byte[] ivForDecryption = Base64.getDecoder().decode(ivBase64);
            IvParameterSpec ivspec = new IvParameterSpec(ivForDecryption);
            return ivspec;
        }
        throw new RuntimeException("Invalid type! " + type);
    }

    private byte[] appendIvToResult(byte[] iv, byte[] result) {
        byte[] resultWithIv = new byte[iv.length + result.length];
        System.arraycopy(iv, 0, resultWithIv, 0, iv.length);
        System.arraycopy(result, 0, resultWithIv, iv.length, result.length);
        return resultWithIv;
    }

    private boolean isPaddingMode(int mode) {
        if (mode == ModeSelection.DES_CBC_PKCS5_PADDING || mode == ModeSelection.DES_ECB_PKCS5_PADDING) {
            return true;
        }
        return false;
    }

    private byte[] getBytes(String text, int type, int mode) {
        byte[] bytes = text.getBytes();
        if (type == TypeSelectionChoice.ENCRYPT) {
            if (isPaddingMode(mode)) {
                int paddingLength = 8 - (bytes.length % 8);
                byte[] paddedBytes = new byte[bytes.length + paddingLength];
                System.arraycopy(bytes, 0, paddedBytes, 0, bytes.length);
                for (int i = bytes.length; i < paddedBytes.length; i++) {
                    paddedBytes[i] = (byte) paddingLength;
                }
                return paddedBytes;
            }
            else {
                return bytes;
            }
        }

        return bytes;
    }


    /**
     * Read input from users. And then do the respective actions based on the input. 
     *
     * @param type             the type of action to perform (encode or decode)
     * @param mode       the mode choice for the cipher algorithm
     * @param keyFilePath      the file path of the key file
     * @param fileToProcessPath the file path of the file to process
     */
    private void doActionDES(int type, int mode, String keyFilePath, String fileToProcessPath) {
        
        try {
            long startTime = System.currentTimeMillis();

            String keyContent = getFileContent(keyFilePath);
            String fileToProcessContent = getFileContent(fileToProcessPath);
            
            // PrintUtils.printInlineWithColor("Key: " ,PrintUtils.ConsoleColors.BLUE_BRIGHT);
            // PrintUtils.printInlineWithColor(keyContent + "\n");
            // PrintUtils.printInlineWithColor("File content: ", PrintUtils.ConsoleColors.BLUE_BRIGHT);
            // PrintUtils.printInlineWithColor(fileToProcessContent + "\n");

            Cipher cipher;
            
            switch (mode) {
                case ModeSelection.DES_CBC_NO_PADDING:
                    cipher = Cipher.getInstance("DES/CBC/NoPadding");
                    break;
                case ModeSelection.DES_CBC_PKCS5_PADDING: 
                    cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                    break;
                case ModeSelection.DES_ECB_NO_PADDING:
                    cipher = Cipher.getInstance("DES/ECB/NoPadding");
                    break;
                case ModeSelection.DES_ECB_PKCS5_PADDING:
                    cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                    break;
                default:
                    throw new Exception("Invalid mode choice!");
            }

            String textResult = "";

            switch(type) {
                case TypeSelectionChoice.DECRYPT:
                    textResult = decrypt(cipher, type, mode, keyContent, fileToProcessContent);
                    break;
                case TypeSelectionChoice.ENCRYPT:
                    textResult = encrypt(cipher, type, mode, keyContent, fileToProcessContent);
                    break;
            }

            // write out the result to file, if decrypt output.dec else output.enc
            dumpOutputToFile(type, textResult);
            printTimePassed(startTime, System.currentTimeMillis());
        }
        catch(InvalidKeyException e) {
            PrintUtils.printWithColor("The key is invalid!", PrintUtils.ConsoleColors.RED);
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        catch(Exception e) {
            PrintUtils.printWithColor("An error occurred!", PrintUtils.ConsoleColors.RED);
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    /**
     * 
     * @param filePath the path of the file to read
     * @return the content of the file
     */
    private String getFileContent(String filePath) {
        File file = new File(filePath);
        if (!file.exists()) {
            return "";
        }
        StringBuilder contentBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line);
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }
		
        return contentBuilder.toString();
    }

    
    private boolean validateModeSelection(int choice) {
        List<Integer> validModes = new ArrayList<Integer>();
        validModes.add(ModeSelection.DES_CBC_NO_PADDING);
        validModes.add(ModeSelection.DES_CBC_PKCS5_PADDING);
        validModes.add(ModeSelection.DES_ECB_NO_PADDING);
        validModes.add(ModeSelection.DES_ECB_PKCS5_PADDING);
        if (validModes.contains(choice)) {
            return true;
        }
        return false;
    }

    private String fileToProcessPathInput() {
        boolean valid = false;
        PrintUtils.printWithColor("------- Please enter the file path -------", PrintUtils.ConsoleColors.GREEN);
        try {
            while (!valid) {
                try {
                    PrintUtils.printInlineWithColor("Type here: ");
                    String filePath = scanner.nextLine();
                    valid = validateFilePath(filePath);
                    if (valid) {
                        return filePath;
                    }
                }
                catch(Exception e) {
                    PrintUtils.printWithColor("Invalid Choice! Please choose again.", PrintUtils.ConsoleColors.YELLOW_BRIGHT);;
                    scanner.nextLine();
                }
            }
        }
        finally {}
        return "";
    }

    private String keyFileNameInput() {
        boolean valid = false;
        PrintUtils.printWithColor("------- Please enter the file containing key path -------", PrintUtils.ConsoleColors.GREEN);

        try {
            while (!valid) {
                try {
                    PrintUtils.printInlineWithColor("Type here: ");
                    String filePath = scanner.nextLine();
                    valid = validateFilePath(filePath);
                    if (valid) {
                        return filePath;
                    }
                }
                catch(Exception e) {
                    PrintUtils.printWithColor("Invalid Choice! Please choose again.", PrintUtils.ConsoleColors.YELLOW_BRIGHT);
                    e.printStackTrace();
                }
            }
        }
        finally {}
        return "";
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

    private String getResourceFolderPath() {
        String currentPath = Paths.get("").toAbsolutePath().toString();
        String resourceFolderPath = currentPath + File.separator + "resources" + File.separator;
        if (!new File(resourceFolderPath).exists()) {
            new File(resourceFolderPath).mkdir();
        }
        return resourceFolderPath;
    }

    private void printTimePassed (long startTimeMillis, long endTimeMillis) {
        SimpleDateFormat formatter = new SimpleDateFormat("HH:mm:ss:ms");
        // print startTime in format HH:mm:ss
        PrintUtils.printInlineWithColor("Start time: ", PrintUtils.ConsoleColors.BLUE_BRIGHT);
        PrintUtils.printInlineWithColor(formatter.format(new Date(startTimeMillis)) + "\n");
        // print endTime in format HH:mm:ss
        PrintUtils.printInlineWithColor("End time: ", PrintUtils.ConsoleColors.BLUE_BRIGHT);
        PrintUtils.printInlineWithColor(formatter.format(new Date(endTimeMillis)) + "\n");
        
        // print time passed in seconds
        PrintUtils.printInlineWithColor("Time passed: ", PrintUtils.ConsoleColors.BLUE_BRIGHT);
        PrintUtils.printInlineWithColor(calculateDiffTimeInMiliseconds(startTimeMillis, endTimeMillis) + " ms\n");
    }

    private long calculateDiffTimeInMiliseconds(long startTimeMillis, long endTimeMillis) {
        return Math.abs(startTimeMillis - endTimeMillis);
    }

    private String encrypt (Cipher cipher, int type, int mode, String key, String content) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyBytes = key.getBytes();
        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        Key secretKey = keyFactory.generateSecret(desKeySpec);
        IvParameterSpec ivspec = null;
        if (isPaddingMode(mode)){
            ivspec = getIvSpecForCBCCipher(type, mode, key, content);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
        }
        else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        byte[] result = cipher.doFinal(
            getBytes(content, type, mode)
        );
        byte[] base64Result = Base64.getEncoder().encode(result);

        // apend iv to the beginning of the result
        if (isPaddingMode(mode) && ivspec != null) {
            byte[] iv = Base64.getEncoder().encode(ivspec.getIV());
            byte[] resultWithIv = appendIvToResult(iv, base64Result);
            base64Result = resultWithIv;
        }

        String textResult = new String(base64Result, Charset.defaultCharset());
        return textResult;
    }

    private String decrypt (Cipher cipher, int type, int mode, String key, String content) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte [] keyBytes = key.getBytes();
        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        Key secretKey = keyFactory.generateSecret(desKeySpec);
        
        if (!isPaddingMode(mode)){
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        else {
            IvParameterSpec ivspec = getIvSpecForCBCCipher(type, mode, key, content);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
        }

        byte[] bytes = getBytes(content, type, mode);
        
        // remove iv from the beginning of the file content
        byte[] base64Content = new byte[bytes.length - 12];
        if (isPaddingMode(mode)) {
            /**
             * When decoding a Base64 string, every 4 characters represent 3 bytes of data.

                If you want to get 8 bytes of data, you would need a Base64 string that is 11 characters long.

                Here's why:

                8 bytes is 2/3 of 12 bytes.
                Since every 4 Base64 characters represent 3 bytes, you would need 12 Base64 characters to represent 9 bytes.
                But since you only need 8 bytes, you can remove one Base64 character, leaving you with 11 Base64 characters.
                Please note that Base64 encoding requires padding if the number of bytes is not divisible by 3. In this case, the padding character '=' is used. So, if your Base64 string is not a multiple of 4 characters, you would need to add padding to make it valid.
             */

            // remove iv
            base64Content = Arrays.copyOfRange(bytes, 12, bytes.length);
        }
       

        byte[] result = cipher.doFinal(
            Base64.getDecoder().decode(base64Content)
        );

        // remove padding
        if (isPaddingMode(mode)) {
            int paddingLength = result[result.length - 1];
            byte[] resultWithoutPadding = new byte[result.length - paddingLength];
            System.arraycopy(result, 0, resultWithoutPadding, 0, resultWithoutPadding.length);
            result = resultWithoutPadding;
        }

        String textResult = new String(result, StandardCharsets.UTF_8);
        return textResult;
    }


    private void dumpOutputToFile(int type, String textResult) throws IOException {
        String outputFileName = type == TypeSelectionChoice.ENCRYPT ? "output.enc" : "output.dec";
        outputFileName = getResourceFolderPath() + outputFileName;
        PrintUtils.printWithColor("Output will be in the this path: " + outputFileName, PrintUtils.ConsoleColors.GREEN);            
        File outputFile = new File(outputFileName);
        if (!outputFile.exists()) {
            outputFile.createNewFile();
        }
        else {
            outputFile.delete();
            outputFile.createNewFile();
        }
        FileWriter fileWriter = new FileWriter(outputFile);
        fileWriter.write(textResult);
        fileWriter.close();
    }
}
