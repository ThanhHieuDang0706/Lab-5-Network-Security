import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Lab05_1 {
    private static class TypeSelectionChoice {
        static final int DECODE = 1;
        static final int ENCODE = 2;
        static final int EXIT = 3;
    }

    private static class ModeSelection {
        static final int DES_ECB_PKCS5_PADDING = 1;
        static final int DES_ECB_NO_PADDING = 2;
        static final int DES_CBC_PKCS5_PADDING = 3;
        static final int DES_CBC_NO_PADDING =4;
    }

    public static void main(String[] args) throws Exception {
        var lab05_1 = new Lab05_1();
        lab05_1.main();
    }

    public void main() throws Exception {
        Console.printWithColor("Please make sure all files needed are put into resources folder", Console.ConsoleColors.YELLOW);
        Console.printWithColor("----------- Hello, welcome to Lab 05 Part 1 -------------", Console.ConsoleColors.GREEN, Console.ConsoleColors.CYAN_BACKGROUND_BRIGHT);
        Console.printWithColor("----------- Please choose a type of program -------------", Console.ConsoleColors.GREEN);
        int choice = typeSelection();
        int modeChoice = -1;
        if (choice == TypeSelectionChoice.DECODE || choice == TypeSelectionChoice.ENCODE) {
            modeChoice = modeSelection();
        }

    }

    public int typeSelection() {
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.println("3. Exit");
        boolean valid = false;
        try (var scanner = new Scanner(System.in)) {
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
                    System.out.println("Invalid choice, please choose again!");
                    scanner.nextLine();
                }
            }
        }
        return -1;
    }

    private boolean validateTypeSelection(int choice) {
        boolean validChoice = false;
        List<Integer> validTypeSelectionChoice = new ArrayList<Integer>();
        validTypeSelectionChoice.add(TypeSelectionChoice.DECODE);
        validTypeSelectionChoice.add(TypeSelectionChoice.ENCODE);
        validTypeSelectionChoice.add(TypeSelectionChoice.EXIT);
        if (validTypeSelectionChoice.contains(choice)) {
            validChoice = true;
        }
        return validChoice;
    }

    private void encode(int modeChoice) {

    }

    private void decode(int modeChoice) {}

    private int modeSelection() {
        Console.printWithColor("Please select a mode: ", Console.ConsoleColors.GREEN, Console.ConsoleColors.CYAN_BACKGROUND_BRIGHT);
        Console.print("1. DES/ECB/PKCS5Padding");
        Console.print("2. DES/ECB/NoPadding");
        Console.print("3. DES/CBC/PKCS5Padding");
        Console.print("4. View all students");
        Console.print("5. DES/CBC/NoPadding");

        boolean valid = false;
        try (var scanner = new Scanner(System.in)) {
            while (!valid) {
                try {
                    System.out.print("Please type a number: ");
                    int choice = scanner.nextInt();
                    valid = validateModeSelection(choice);
                    if (valid) {
                        return choice;
                    }
                }
                catch(Exception e) {
                    System.out.println("Invalid choice, please choose again!");
                    scanner.nextLine();
                }
            }
        }
        return -1;
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

    private String fileToProcessNameInput() {
        boolean valid = false;
        try (var scanner = new Scanner(System.in)) {
            while (!valid) {
                try {
                    System.out.print("Please type a number: ");
                    String fileName = scanner.next();
                    valid = validateFileName(fileName);
                    if (valid) {
                        return fileName;
                    }
                }
                catch(Exception e) {
                    System.out.println("Invalid choice, please choose again!");
                    scanner.nextLine();
                }
            }
        }
        return "";
    }

    /**
     * @description validate if file exists
     * @param fileName file name to validate in side resources folder
     * @return true if the file exists, false otherwise
     */
    private boolean validateFileName(String fileName) {
        return false;
    }
}
