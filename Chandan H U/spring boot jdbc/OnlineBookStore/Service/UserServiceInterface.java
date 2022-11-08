package example.OnlineBookStore.Service;

import example.OnlineBookStore.Model.User;

public interface UserServiceInterface {
    void createNewAccount(User user);
    void selectBookTOBuy(String userId , String bookNumber , String bookName , int numberOfBooksPurchased);
    void addBooksToCart(String userId , String bookNumber , String bookName);
    void removeBookFromCart(String userId , String bookName);
}
