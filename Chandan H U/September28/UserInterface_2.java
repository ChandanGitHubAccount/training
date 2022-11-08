package September28;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.Map;

public interface UserInterface_2 {
    void addBorrower(ClassPathXmlApplicationContext context , Map<String, Borrower> borrowerDetails);
}
