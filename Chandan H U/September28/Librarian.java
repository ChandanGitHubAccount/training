package September28;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import static September28.LibraryStore.titleOfBook;

public class Librarian implements UserInterface_1 , UserInterface_2 {
    Scanner scan = new Scanner(System.in);
    @Override
    public boolean searchBookByTitle(String bookTitle, Set<String> titleOfBook) {
        return titleOfBook.contains(bookTitle);
    }

    @Override
    public void viewBookBorrowedHistory(Map<String, Borrower> borrowerDetails) {
        System.out.println("Book borrowed history :\n");
        for (String key : borrowerDetails.keySet())
            System.out.println("borrowerId : " + borrowerDetails.get(key).getBorrowerId() +
                    "\nborrowerName : " + borrowerDetails.get(key).getBorrowerName() +
                    "\nbookBorrowedHistory : " + borrowerDetails.get(key).getBookBorrowedHistory() +
                                "\nfinePaidTOLibrary : " + borrowerDetails.get(key).getFinePaidTOLibrary() + "\n");
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

    void addBookTOLibrary(ClassPathXmlApplicationContext context){
        System.out.println("Enter the book title you want to add.");
        String bookTitle = scan.next();
        titleOfBook.add(bookTitle);
    }

    public void deleteBook() {
        System.out.println("Enter the book title  you want to delete.");
        String bookTitle = scan.next();
        for(String value : titleOfBook)
            if (bookTitle.equalsIgnoreCase(value))
                titleOfBook.remove(bookTitle);
    }
}
