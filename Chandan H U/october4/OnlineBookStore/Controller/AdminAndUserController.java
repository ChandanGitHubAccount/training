package example.OnlineBookStore.Controller;

import example.OnlineBookStore.Model.AdminBookStore;
import example.OnlineBookStore.Model.User;
import example.OnlineBookStore.Service.AdminServiceInterface;
import example.OnlineBookStore.Service.CommonInterfaceForUserAndAdmin;
import example.OnlineBookStore.Service.UserServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
public class AdminAndUserController {
    //Admin
    @Autowired
    CommonInterfaceForUserAndAdmin interfaceForAdmin;

    @Autowired
    AdminServiceInterface adminServiceInterface;


    @GetMapping("/viewAvailableBooksInStore/admin")
    public ResponseEntity<List<AdminBookStore>> viewAvailableBooks() {
        try {
            return ResponseEntity.of(Optional.of(interfaceForAdmin.viewAvailableBooksInStore()));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @PostMapping("/addBookDetails:")
    public ResponseEntity<Void> addBook(@RequestBody AdminBookStore book) {
        try {
            adminServiceInterface.addBookToStore(book);
            ResponseEntity.ok();
        } catch (Exception exception) {
            ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        return null;
    }

    @DeleteMapping("/deleteBook/{bookNumber}")
    public ResponseEntity<Void> deleteBookFromStore(@PathVariable String bookNumber){
        try {
            adminServiceInterface.removeBookFromStore(bookNumber);
            ResponseEntity.ok();
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return null;
    }

    @PutMapping("/updateBookPrice/{bookNumber}")
    public ResponseEntity<Void> updateBookPriceByAdmin(@PathVariable String bookNumber , @RequestBody int bookPrice){
        try{
            adminServiceInterface.updateBookPrice(bookNumber,bookPrice);
            ResponseEntity.ok();
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        return null;
    }

    //----------------------------------------User--------------------------------

    @Autowired
    UserServiceInterface userServiceInterface;

    @GetMapping("/viewAvailableBooksInStore/user")
    public ResponseEntity<List<AdminBookStore>> viewAvailableBook() {
        try {
            return ResponseEntity.of(Optional.of(interfaceForAdmin.viewAvailableBooksInStore()));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @PostMapping("/createAccount:")
    public ResponseEntity<Void> createUserAccount(@RequestBody User user){
        try{
            userServiceInterface.createNewAccount(user);
            ResponseEntity.ok();
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return null;
    }

    @PostMapping("/buyBookFromStore/{userId}/{bookNumber}/{bookName}")
    public ResponseEntity<Void> purchaseBookFromStore(@PathVariable String userId , @PathVariable String bookNumber ,
                                                      @PathVariable String bookName , @RequestBody int numberOfBooksPurchased){
        try{
            userServiceInterface.selectBookTOBuy(userId,bookNumber,bookName,numberOfBooksPurchased);
            ResponseEntity.ok();
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return null;
    }

    @PostMapping("/addBooksToCart/{userId}/{bookNumber}/{bookName}")
    public ResponseEntity<Void> addBooksToShoppingCart(@PathVariable String userId , @PathVariable String bookNumber ,
                                                       @PathVariable String bookName){
        try{
            userServiceInterface.addBooksToCart(userId,bookNumber,bookName);
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return null;
    }

    @DeleteMapping("/deleteBooksFromCart/{userId}/{bookNumber}")
    public ResponseEntity<Void> deleteBooksFromShoppingCart(@PathVariable String userId , @PathVariable String bookNumber){
        try{
            userServiceInterface.removeBookFromCart(userId,bookNumber);
            ResponseEntity.ok();
        }catch (Exception exception){
            ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return null;
    }

}
