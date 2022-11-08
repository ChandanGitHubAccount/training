package example.OnlineBookStore.Service;

import example.OnlineBookStore.Model.AdminBookStore;

public interface AdminServiceInterface {
    void addBookToStore(AdminBookStore book);
    void removeBookFromStore(String bookNumber);
    void updateBookPrice(String bookNumber , int bookPrice);
}
