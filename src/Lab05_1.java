import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.InputMismatchException;

/**
 * This class represents Lab05_1, which is a program for network security.
 * It provides functionality for encryption and decryption using different modes
 * and algorithms.
 * The program prompts the user to choose the type of program (encryption or
 * decryption),
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
            } catch (Exception e) {
                PrintUtils.printWithColor("An error occurred!", PrintUtils.ConsoleColors.RED);
                e.printStackTrace();
            }
        }
    }

    /**
     * The main method of the Lab05_1 class.
     * This method is the entry point of the program.
     * It prompts the user to choose a type of program and performs the
     * corresponding actions based on the user's choice.
     * If the user chooses to exit the program, it terminates the program.
     * If the user chooses to encode or decode, it prompts the user to choose a mode
     * and performs the corresponding actions based on the user's choice.
     * It also prompts the user to enter the name of the file to process and the
     * name of the key file.
     * 
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

        doDESAction(choice, modeChoice, keyFileName, fileToProcessPathInput);
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
                        PrintUtils.printWithColor("Invalid Choice! Please choose again.",
                                PrintUtils.ConsoleColors.YELLOW_BRIGHT);
                        ;
                        if (scanner.hasNext()) {
                            scanner.nextLine();
                        }
                    }

                } catch (InputMismatchException e) {
                    PrintUtils.printWithColor("Invalid Choice! Please choose again.",
                            PrintUtils.ConsoleColors.YELLOW_BRIGHT);
                    ;
                    if (scanner.hasNextLine()) {
                        scanner.nextLine();
                    }
                }
            }
        } finally {
        }
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

    private IvParameterSpec getIvSpecForCBCCipher(int type, int mode, byte[] data) {
        if (type == TypeSelectionChoice.ENCRYPT) {
            byte[] iv = new byte[8]; // 8 bytes for DES
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            return ivspec;
        }
        if (type == TypeSelectionChoice.DECRYPT) {
            byte[] ivForDecryption = Arrays.copyOfRange(data, 0, 8);
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

    private boolean isCbcMode(int mode) {
        if (mode == ModeSelection.DES_CBC_PKCS5_PADDING || mode == ModeSelection.DES_CBC_NO_PADDING) {
            return true;
        }
        return false;
    }

    private byte[] getBytesWithPaddingIfNeeded(byte[] bytes, int type, int mode) {
        if (type == TypeSelectionChoice.ENCRYPT) {
            // add padding if mode is padding
            if (isPaddingMode(mode)) {
                int paddingLength = 8 - (bytes.length % 8);
                byte[] paddedBytes = new byte[bytes.length + paddingLength];
                System.arraycopy(bytes, 0, paddedBytes, 0, bytes.length);
                for (int i = bytes.length; i < paddedBytes.length; i++) {
                    paddedBytes[i] = (byte) paddingLength;
                }
                return paddedBytes;
            } else {
                return bytes;
            }
        }

        if (type == TypeSelectionChoice.DECRYPT) {
            return bytes;
        }

        return bytes;
    }

    private Key getSecretKey(byte[] keyBytes) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        SecretKeySpec desKeySpec = new SecretKeySpec(keyBytes, "DES");
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        Key secretKey = keyFactory.generateSecret(desKeySpec);
        return secretKey;
    }

    /**
     * Read input from users. And then do the respective actions based on the input.
     *
     * @param type              the type of action to perform (encode or decode)
     * @param mode              the mode choice for the cipher algorithm
     * @param keyFilePath       the file path of the key file
     * @param fileToProcessPath the file path of the file to process
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws InterruptedException
     * @throws Exception
     */
    private void doDESAction(int type, int mode, String keyFilePath, String fileToProcessPath)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException,
            InterruptedException, IOException {

        long startTime = System.currentTimeMillis();

        byte[] keyContent = getFileContent(keyFilePath);
        Key secretKey = getSecretKey(keyContent);

        IvParameterSpec ivspec = null;
        Cipher cipher;
        boolean initCipher = false;

        switch (mode) {
            case ModeSelection.DES_CBC_NO_PADDING:
                cipher = Cipher.getInstance("DES/CBC/NOPADDING");
                break;
            case ModeSelection.DES_CBC_PKCS5_PADDING:
                cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                break;
            case ModeSelection.DES_ECB_NO_PADDING:
                cipher = Cipher.getInstance("DES/ECB/NOPADDING");
                break;
            case ModeSelection.DES_ECB_PKCS5_PADDING:
                cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
                break;
            default:
                throw new RuntimeException("Invalid mode choice!");
        }

        File file = new File(fileToProcessPath);
        if (!file.exists()) {
            PrintUtils.printWithColor("File does not exist!", PrintUtils.ConsoleColors.RED);
            return;
        }

        // ExecutorService executor = Executors.newFixedThreadPool(16);
        var results = new ConcurrentSkipListMap<Integer, byte[]>();

        try (FileChannel fc = new FileInputStream(fileToProcessPath).getChannel()) {
            final int MAP_SIZE = 1024 * 1024 * 32;

            long fileSize = fc.size();
            long position = 0;
            int lineNum = 0;
            while (position < fileSize) {
                long remaining = fileSize - position;
                int bytesToMap = (int) Math.min(MAP_SIZE, remaining);

                MappedByteBuffer bb = fc.map(FileChannel.MapMode.READ_ONLY, position, bytesToMap);
                byte[] bytes = new byte[bytesToMap];
                bb.get(bytes, 0, bytesToMap);

                // init cipher if not already init
                if (!initCipher) {
                    if (isCbcMode(mode)) {
                        ivspec = getIvSpecForCBCCipher(type, mode, bytes);
                    }

                    if (isCbcMode(mode)) {
                        cipher.init(type == TypeSelectionChoice.ENCRYPT ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                                secretKey, ivspec);
                    } else {
                        cipher.init(type == TypeSelectionChoice.ENCRYPT ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                                secretKey);
                    }
                    initCipher = true;
                }

                final int finalLineNum = lineNum;

                final boolean finalChunk = position + (long) bytesToMap >= fileSize;

                byte[] result = null;

                try {
                    switch (type) {
                        case TypeSelectionChoice.DECRYPT:
                            result = decrypt(cipher, type, mode, secretKey, bytes, finalChunk);
                            break;
                        case TypeSelectionChoice.ENCRYPT:
                            result = encrypt(cipher, type, mode, secretKey, bytes, finalChunk);
                            break;
                    }

                } catch (InvalidKeyException e) {
                    PrintUtils.printWithColor("The key is invalid!", PrintUtils.ConsoleColors.RED);
                    e.printStackTrace();
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    PrintUtils.printWithColor("There is an error!",
                            PrintUtils.ConsoleColors.RED);
                    e.printStackTrace();
                }
                results.put(finalLineNum, result);

                position += bytesToMap;
                ++lineNum;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // executor.shutdown();
        // executor.awaitTermination(Long.MAX_VALUE, TimeUnit.MILLISECONDS);

        for (Map.Entry<Integer, byte[]> entry : results.entrySet()) {
            dumpOutputToFile(type, entry.getValue(), entry.getKey() == 0);
        }
        PrintUtils.printWithColor(getOuptputFileName(type) + " is created!", PrintUtils.ConsoleColors.GREEN);
        printTimePassed(startTime, System.currentTimeMillis());
    }

    private byte[] getFileContent(String filePath) {
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

        return fileContent;
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

        while (!valid) {
            try {
                PrintUtils.printInlineWithColor("Type here: ");
                String filePath = scanner.nextLine();
                valid = validateFilePath(filePath);
                if (valid) {
                    return filePath;
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

    private String keyFileNameInput() {
        boolean valid = false;
        PrintUtils.printWithColor("------- Please enter the file containing key path -------",
                PrintUtils.ConsoleColors.GREEN);

        while (!valid) {
            try {
                PrintUtils.printInlineWithColor("Type here: ");
                String filePath = scanner.nextLine();
                valid = validateFilePath(filePath);
                if (valid) {
                    return filePath;
                }
            } catch (Exception e) {
                PrintUtils.printWithColor("Invalid Choice! Please choose again.",
                        PrintUtils.ConsoleColors.YELLOW_BRIGHT);
                e.printStackTrace();
            }
        }

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

    private void printTimePassed(long startTimeMillis, long endTimeMillis) {
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

    
    /**
     * @param cipher cipher object
     * @param type type of action (encrypt or decrypt)
     * @param mode mode of operation
     * @param secretKey secret key 
     * @param content content to encrypt or decrypt
     * @param finalChunk true if this is the final chunk, false otherwise
     * @return encrypted or decrypted content
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @description encrypt content
     * @description if mode is CBC, append iv to the beginning of the result
     * @description if mode is padding, add padding to the content ON EACH CHUNK if there are multiple chunks
     */
    private byte[] encrypt(Cipher cipher, int type, int mode, Key secretKey, byte[] content, boolean finalChunk)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        IvParameterSpec ivspec = null;

        if (isCbcMode(mode)) {
            ivspec = getIvSpecForCBCCipher(type, mode, content);
        }

        byte[] dataWithPaddingIfNeeded = getBytesWithPaddingIfNeeded(content, type, mode);

        byte[] result = finalChunk ? cipher.doFinal(dataWithPaddingIfNeeded) : cipher.update(dataWithPaddingIfNeeded);

        // apend iv to the beginning of the result
        if (isCbcMode(mode)) {
            byte[] iv = ivspec.getIV();
            byte[] resultWithIv = appendIvToResult(iv, result);
            result = resultWithIv;
        }

        return result;
    }

    /**
     * @param bytes
     * @description print byte array to console, this was intended for debug
     */
    private void printByteArray(byte[] bytes) {
        for (byte b : bytes) {
            System.out.print(b + " ");
        }
        System.out.println();
    }

    /**
     * Decrypts the given content using the specified cipher, type, mode, secret key, and final chunk flag.
     *
     * @param cipher          the cipher used for decryption
     * @param type            the type of encryption algorithm
     * @param mode            the mode of encryption
     * @param secretKey       the secret key used for decryption
     * @param content         the content to be decrypted
     * @param finalChunk      a flag indicating whether it is the final chunk of data
     * @return the decrypted byte array
     * @throws IllegalBlockSizeException             if the block size is invalid
     * @throws BadPaddingException                   if the padding is invalid
     * @throws InvalidKeyException                   if the secret key is invalid
     * @throws InvalidAlgorithmParameterException    if the algorithm parameters are invalid
     * @throws NoSuchAlgorithmException              if the encryption algorithm is not available
     * @throws InvalidKeySpecException               if the secret key specification is invalid
     * @throws InvalidAlgorithmParameterException    if the algorithm parameters are invalid
     * @throws IllegalBlockSizeException             if the block size is invalid
     * @throws BadPaddingException                   if the padding is invalid
     * @description decrypt content
     * @description if mode is CBC, remove iv from the beginning of the content
     * @description if mode is padding, remove padding from the content ON THE FINAL CHUNK
     */
    private byte[] decrypt(Cipher cipher, int type, int mode, Key secretKey, byte[] content, boolean finalChunk)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytesWithPaddingIfNeeded = getBytesWithPaddingIfNeeded(content, type, mode);

        // remove iv from the beginning of the file content
        byte[] data;
        if (isCbcMode(mode)) {
            data = new byte[bytesWithPaddingIfNeeded.length - 8];
            data = Arrays.copyOfRange(bytesWithPaddingIfNeeded, 8, bytesWithPaddingIfNeeded.length);
        } else {
            data = bytesWithPaddingIfNeeded;
        }

        byte[] result = null;

        result = finalChunk ? cipher.doFinal(data) : cipher.update(data);

        // remove padding
        if (isPaddingMode(mode) && finalChunk) {
            // remove padding
            int paddingLength = result[result.length - 1] & 0xFF; // Ensure it's treated as unsigned

            if (paddingLength > 0 && paddingLength <= result.length) {
                byte[] resultWithoutPadding = new byte[result.length - paddingLength];
                System.arraycopy(result, 0, resultWithoutPadding, 0, result.length -
                paddingLength);
                result = resultWithoutPadding;
            }
        }

        return result;
    }

    private String getOuptputFileName(int type) {
        String outputFileName = type == TypeSelectionChoice.ENCRYPT ? "output.enc" : "output.dec";
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
}
