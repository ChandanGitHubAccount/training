package September28;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class Clerk implements UserInterface_1, UserInterface_2 {
    Scanner scan = new Scanner(System.in);
    @Override
    public boolean searchBookByTitle(String bookTitle, Set<String> titleOfBook) {
            return LibraryStore.titleOfBook.contains(bookTitle);
    }

    @Override
    public void viewBookBorrowedHistory(Map<String, Borrower> borrowerDetails) {
        System.out.println("Enter the borrower id to view borrow history.");
        String id = scan.next();
        if (borrowerDetails.containsKey(id))
            System.out.println("bookBorrowedHistory : " + borrowerDetails.get(id).getBookBorrowedHistory());
        else System.out.println("Borrower not registered in the library.");
    }

    @Override
    public void addBorrower(ClassPathXmlApplicationContext context, Map<String, Borrower> borrowerDetails) {
        Borrower borrower = new Borrower();
        System.out.println("Enter the name and id of borrower.");
        String borrowerName = scan.next();
        String borrowerId = scan.next();
        borrower.setBorrowerName(borrowerName);
        borrower.setBorrowerId(borrowerId);
        borrowerDetails.put(borrowerId, borrower);
    }

    public void recordFineDetailsDuringReturnOfBorrowedBook(Map<String, Borrower> borrowerDetails) {
        System.out.println("Enter the borrower id.");
        String borrowerId = scan.next();
        if (borrowerDetails.containsKey(borrowerId))
            borrowerDetails.get(borrowerId).setFinePaidTOLibrary(100);
        else System.out.println("Invalid borrower id.");
    }

    public String getApproveForBookLoan() {
        System.out.println("Enter YES to loan book else NO for reject request.");
        return scan.next();
    }
}
