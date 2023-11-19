import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import javax.crypto.Cipher;
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

        doAction(choice, modeChoice, keyFileName, fileToProcessPathInput);
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
            byte[] ivForDecryption = Arrays.copyOfRange(content.getBytes(), 0, 8);
            IvParameterSpec ivspec = new IvParameterSpec(ivForDecryption);
            return ivspec;
        }
        throw new RuntimeException("Invalid type! " + type);
    }

    /**
     * Read input from users. And then do the respective actions based on the input. 
     *
     * @param type             the type of action to perform (encode or decode)
     * @param modeChoice       the mode choice for the cipher algorithm
     * @param keyFilePath      the file path of the key file
     * @param fileToProcessPath the file path of the file to process
     */
    private void doAction(int type, int modeChoice, String keyFilePath, String fileToProcessPath) {
        
        try {
            long startTime = System.currentTimeMillis();

            String keyContent = getFileContent(keyFilePath);
            String fileToProcessContent = getFileContent(fileToProcessPath);
            
            // PrintUtils.printInlineWithColor("Key: " ,PrintUtils.ConsoleColors.BLUE_BRIGHT);
            // PrintUtils.printInlineWithColor(keyContent + "\n");
            // PrintUtils.printInlineWithColor("File content: ", PrintUtils.ConsoleColors.BLUE_BRIGHT);
            // PrintUtils.printInlineWithColor(fileToProcessContent + "\n");

            byte[] keyBytes = keyContent.getBytes();
            DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
     
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            Key secretKey = keyFactory.generateSecret(desKeySpec);
            
            Cipher cipher;
            
            switch (modeChoice) {
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

            cipher.init(type == TypeSelectionChoice.ENCRYPT ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
            
            // do the encryption/decryption and measure execution time here
            byte[] result = cipher.doFinal(type ==TypeSelectionChoice.ENCRYPT ? fileToProcessContent.getBytes() : Base64.getDecoder().decode(fileToProcessContent));

            byte[] basde64Result = Base64.getEncoder().encode(result);
            String textResult = type == TypeSelectionChoice.ENCRYPT ? new String(basde64Result, StandardCharsets.UTF_8) : new String(result, StandardCharsets.UTF_8);

            // For debugging purporse
            // if (type == TypeSelectionChoice.ENCRYPT) {
            //     PrintUtils.printWithColor("The encoded result is: ", PrintUtils.ConsoleColors.GREEN);
            //     PrintUtils.print(textResult);
            // }
            // else {
            //     PrintUtils.printWithColor("The decoded result is: ", PrintUtils.ConsoleColors.GREEN);
            //     PrintUtils.print(textResult);
            // }

            // write out the result to file, if decrypt output.dec else output.enc
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
}
