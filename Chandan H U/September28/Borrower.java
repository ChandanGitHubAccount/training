package September28;

import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import static September28.LibraryStore.titleOfBook;

public class Borrower implements UserInterface_1 {
    Clerk clerk;
    Scanner scan = new Scanner(System.in);
    private String borrowerName, borrowerId;
    private String bookBorrowedHistory ;
    private int finePaidTOLibrary = 0;

    public int getFinePaidTOLibrary() {
        return finePaidTOLibrary;
    }

    public void setFinePaidTOLibrary(int finePaidTOLibrary) {
        this.finePaidTOLibrary = finePaidTOLibrary;
    }

    public String getBookBorrowedHistory() {
        return bookBorrowedHistory;
    }

    public void setBookBorrowedHistory(String bookBorrowedHistory) {
        this.bookBorrowedHistory = bookBorrowedHistory;
    }

    public String getBorrowerName() {
        return borrowerName;
    }

    public void setBorrowerName(String borrowerName) {
        this.borrowerName = borrowerName;
    }

    public String getBorrowerId() {
        return borrowerId;
    }

    public void setBorrowerId(String borrowerId) {
        this.borrowerId = borrowerId;
    }

    @Override
    public boolean searchBookByTitle(String bookTitle, Set<String> titleOfBook) {
        return titleOfBook.contains(bookTitle);
    }

    @Override
    public void viewBookBorrowedHistory(Map<String, Borrower> borrowerDetails) {
        System.out.println("Enter the borrower id to view borrow history.");
        String id = scan.next();
        for (String key : borrowerDetails.keySet())
            if (borrowerDetails.get(key).getBorrowerId().equals(id))
                System.out.println(borrowerDetails.get(key).getBookBorrowedHistory() + "\n");
            else System.out.println("Borrower not registered in the library.");

    }

    public void requestForBookToLoan(Map<String, Borrower> borrowerDetails) {
        System.out.println("Enter the Borrower id.");
        String bookTitle,borrowersId=scan.next();
        if (borrowerDetails.containsKey(borrowersId)) {
            System.out.println("Enter the book title you want to search.");
            bookTitle = scan.next();
            if (searchBookByTitle(bookTitle,titleOfBook))
                if ("YES".equalsIgnoreCase(clerk.getApproveForBookLoan())) {
                    System.out.println("you can borrow the book.");
                    updateBorrowedHistory(bookTitle);
                } else System.out.println("Your request is rejected.");
            else
                System.out.println("Entered book not available");
        }
        else
            System.out.println("Entered wrong borrower id.");
    }

    public void updateBorrowedHistory(String bookTitle) {
        setBookBorrowedHistory(getBookBorrowedHistory() + "\n" + bookTitle + " is borrowed");
    }

    public void returnBorrowedBook() {
        System.out.println("Enter the book title you want to search.");
        String bookTitle = scan.next();
        if(searchBookByTitle(bookTitle, titleOfBook ))
            System.out.println("Book returned.");
        else System.out.println("Entered book title is invalid.");
    }
}
