package September28;

import java.util.Map;
import java.util.Set;

public interface UserInterface_1 {
    boolean searchBookByTitle(String bookTitle , Set<String> titleOfBook);

    void viewBookBorrowedHistory(Map<String, Borrower> borrowerDetails);
}
