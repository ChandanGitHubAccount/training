package zomato.contoller.admincontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.coustomexcptions.UpdateFailedException;
import zomato.model.Menu;
import zomato.service.restaurant.MenuInterface;

import java.io.IOException;
import java.util.Optional;

@RestController
@RequestMapping("/restaurant")
public class MenuController {

    /**
     * Menu controller
     */

    @Autowired
    private MenuInterface menuInterface;

    @PostMapping("/register-menu")
    public ResponseEntity<String> addMenu(@ModelAttribute Menu menu, @RequestParam MultipartFile dishPhoto) throws SessionIdExpiredException, IOException {
        return ResponseEntity.of(Optional.of(menuInterface.addMenu(menu, dishPhoto)));
    }

    @PatchMapping("change-description")
    public ResponseEntity<String> changeDescription(@RequestParam String itemName, @RequestParam String categoryName,
                                                    @RequestParam String description) throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(menuInterface.changeDescription(itemName, categoryName, description)));
    }

    @PatchMapping("change-dish-photo")
    public ResponseEntity<String> changeDishPhoto(@RequestParam String itemName, @RequestParam String categoryName,
                                                  @RequestParam MultipartFile dishPhoto) throws SessionIdExpiredException, UpdateFailedException, IOException {
        return ResponseEntity.of(Optional.of(menuInterface.changeDishPhoto(itemName, categoryName, dishPhoto)));
    }

    @PatchMapping("change-dish-price")
    public ResponseEntity<String> changeDishPrice(@RequestParam String itemName, @RequestParam String categoryName,
                                                  @RequestParam int itemPrice) throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(menuInterface.changeDishPrice(itemName, categoryName, itemPrice)));
    }

    @PatchMapping("change-category")
    public ResponseEntity<String> changeCategory(@RequestParam String itemName, @RequestParam String oldCategoryName,
                                                 @RequestParam String newCategoryName) throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(menuInterface.changeCategory(itemName, oldCategoryName, newCategoryName)));
    }

    @DeleteMapping("remove-menu")
    public ResponseEntity<String> removeMenu(@RequestParam String itemName, @RequestParam String categoryName) throws UpdateFailedException, SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(menuInterface.removeMenu(itemName, categoryName)));
    }

    @DeleteMapping("/remove-dish-photo")
    public ResponseEntity<String> deleteOldPhoto(@RequestParam String itemName, @RequestParam String categoryName) throws IOException, SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(menuInterface.deleteOldPhoto(itemName, categoryName)));
    }

}
