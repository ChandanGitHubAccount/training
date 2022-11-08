package September28;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import static September28.LibraryStore.titleOfBook;

public class LibraryServer {
    static ClassPathXmlApplicationContext context;
    static Scanner scan = new Scanner(System.in);
    //Object of all classes
    static Librarian librarian = new Librarian();
    static Clerk clerk = new Clerk();
    static Borrower borrower = new Borrower();

    //User map to store borrower details
    static Map<String, Borrower> borrowerDetails = new HashMap<>(

    );

    public static void main(String[] args) {
        while (true) {
            System.out.println("""
                                Select
                                1:Librarian.
                                2:Clerk.
                                3:Borrower.
                                4:Exit.""");
            int choice = scan.nextInt();
            switch (choice) {
                case 1 -> librarianLogin();
                case 2 -> clerkLogin();
                case 3 -> borrowerLogin();
                case 4 -> {return;}
                default -> System.out.println("Please select proper options.");
            }
        }

    }

    private static void borrowerLogin() {
        System.out.println("""
                Enter
                1::Search book.
                2:View borrowers history.
                3:Request to borrow thw book
                4:Return the borrowed book""");
        int borrowerChoice = scan.nextInt();
        switch (borrowerChoice) {
            case 1 -> {
                System.out.println("Enter the book title you want to search.");
                String bookTitle = scan.next();
                if(borrower.searchBookByTitle(bookTitle,titleOfBook ))
                    System.out.println(bookTitle + " - is present in library.");
                else System.out.println(bookTitle + " - book is not available in library.");
            }
            case 2 -> borrower.viewBookBorrowedHistory(borrowerDetails);
            case 3 -> borrower.requestForBookToLoan(borrowerDetails);
            case 4 -> borrower.returnBorrowedBook();
            default -> System.out.println("Please select proper options.");
        }
    }

    private static void clerkLogin() {

        System.out.println("""
                Select
                1:Add borrower.
                2:Search book.
                3:View borrowers history.
                4:Record fine details.""");
        int clerkChoice = scan.nextInt();
        switch (clerkChoice) {
            case 1 -> clerk.addBorrower(context , borrowerDetails);
            case 2 -> {
                System.out.println("Enter the book title you want to search.");
                String bookTitle = scan.next();
                if(clerk.searchBookByTitle(bookTitle,titleOfBook ))
                    System.out.println(bookTitle + " - is present in library.");
                else System.out.println(bookTitle + " - book is not available in library.");
            }
            case 3 -> clerk.viewBookBorrowedHistory(borrowerDetails);
            case 4 -> clerk.recordFineDetailsDuringReturnOfBorrowedBook(borrowerDetails);
            default -> System.out.println("Please select proper options.");
        }
    }

    private static void librarianLogin() {

        System.out.println("""
                Select
                1:Add new book.
                2:Add new borrower.
                3:Delete book.
                4:Search book.
                5:View borrowers history.""");
        int librarianChoice = scan.nextInt();
        switch (librarianChoice) {
            case 1 -> librarian.addBookTOLibrary(context);
            case 2 -> librarian.addBorrower(context , borrowerDetails);
            case 3 -> librarian.deleteBook();
            case 4 -> {
                System.out.println("Enter the book title you want to search.");
                String bookTitle = scan.next();
                if(librarian.searchBookByTitle(bookTitle,titleOfBook ))
                    System.out.println(bookTitle + " - is present in library.");
                else System.out.println(bookTitle + " - book is not available in library.");
            }
            case 5 -> librarian.viewBookBorrowedHistory(borrowerDetails);
            default -> System.out.println("Please select proper options.");
        }
    }
}
