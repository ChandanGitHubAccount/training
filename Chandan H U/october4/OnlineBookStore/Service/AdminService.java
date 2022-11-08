package example.OnlineBookStore.Service;

import example.OnlineBookStore.Model.AdminBookStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Primary
public class AdminService implements AdminServiceInterface,CommonInterfaceForUserAndAdmin{
    @Autowired
    JdbcTemplate jdbcTemplate;
    @Override
    public List<AdminBookStore> viewAvailableBooksInStore() {
        try {
            return jdbcTemplate.query("SELECT * FROM bookstore",
                    new BeanPropertyRowMapper<>(AdminBookStore.class));
        } catch (Exception exception) {
            System.out.println("student details not found.");
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public void addBookToStore(AdminBookStore book) {
        try {
            jdbcTemplate.update("INSERT INTO bookstore VALUES (? , ? , ?, ?)", book.getBookNumber(),
                    book.getBookName(),book.getNumberOfBooks(),book.getBookPrice());
        } catch (Exception exception) {
            System.out.println("User details are invalid.\n" + exception);
        }
    }

    @Override
    public void removeBookFromStore(String bookNumber) {
        jdbcTemplate.update("DELETE FROM bookstore WHERE bookNumber = ?",bookNumber);
    }

    @Override
    public void updateBookPrice(String bookNumber, int bookPrice) {
        jdbcTemplate.update("UPDATE bookstore SET bookPrice = ? WHERE bookNumber = ?",
                bookPrice,bookNumber);
    }
}
