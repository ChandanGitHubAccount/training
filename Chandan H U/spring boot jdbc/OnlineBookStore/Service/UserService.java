package example.OnlineBookStore.Service;

import example.OnlineBookStore.Model.AdminBookStore;
import example.OnlineBookStore.Model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserService implements CommonInterfaceForUserAndAdmin, UserServiceInterface {
    @Autowired
    JdbcTemplate jdbcTemplate;

    @Override
    public List<AdminBookStore> viewAvailableBooksInStore() {
        try {
            return jdbcTemplate.query("SELECT * FROM bookstore", new BeanPropertyRowMapper<>(AdminBookStore.class));
        } catch (Exception exception) {
            System.out.println("student details not found.");
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public void createNewAccount(User user) {
        try {
            jdbcTemplate.update("INSERT INTO user VALUES (? , ? , ?, ?)", user.getUserId(),
                    user.getUserName(), user.getGender(), user.getPhoneNumber());
        } catch (Exception exception) {
            System.out.println("User details are invalid.\n" + exception);
        }
    }

    @Override
    public void selectBookTOBuy(String userId, String bookNumber, String bookName, int numberOfBooksPurchased) {
        try {
            List<AdminBookStore> bookList = viewAvailableBooksInStore();
            List<AdminBookStore> book;
            for (AdminBookStore listOfBook : bookList)
                if (listOfBook.getBookNumber().equals(bookNumber)) {
                    book = jdbcTemplate.query("SELECT * FROM bookstore Where bookNumber = ? ",
                            new BeanPropertyRowMapper<>(AdminBookStore.class), bookNumber);
                    if (book.get(0).getNumberOfBooks() >= numberOfBooksPurchased) {
                        int remainingBooks = book.get(0).getNumberOfBooks() - numberOfBooksPurchased;
                        jdbcTemplate.update("UPDATE bookStore SET numberOfBooks = ?  WHERE bookNumber = ?", remainingBooks, bookNumber);
                        jdbcTemplate.update("INSERT INTO userPurchasedList VALUES (? , ? , ? , ?)", userId, bookNumber, bookName, numberOfBooksPurchased);
                    }
                }
        }catch (Exception exception){
            exception.printStackTrace();
        }
    }

    @Override
    public void addBooksToCart(String userId, String bookNumber, String bookName) {
        try {
            List<User> userList = jdbcTemplate.query("SELECT * FROM User", new BeanPropertyRowMapper<>(User.class));
            List<AdminBookStore> book = jdbcTemplate.query("SELECT * FROM bookstore Where bookNumber = ? ",
                    new BeanPropertyRowMapper<>(AdminBookStore.class), bookNumber);
            for (User user : userList)
                if (user.getUserId().equals(userId) && book.get(0).getBookName().equals(bookName))
                    jdbcTemplate.update("INSERT INTO userShoppingCart VALUES (? , ? , ?)", userId, bookNumber, bookName);
        }catch (Exception exception){
            exception.printStackTrace();
        }
    }

    @Override
    public void removeBookFromCart(String userId, String bookNumber) {
        try {
            jdbcTemplate.update("DELETE FROM userShoppingCart WHERE userID = ? and bookNumber = ?", userId, bookNumber);
        }catch (Exception exception){
            exception.printStackTrace();
        }
    }
}
