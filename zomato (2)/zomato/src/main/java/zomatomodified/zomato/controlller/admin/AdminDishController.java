package zomatomodified.zomato.controlller.admin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import zomatomodified.zomato.coustomexcptions.UpdateFailedException;
import zomatomodified.zomato.model.Dish;
import zomatomodified.zomato.service.admin.DishInterface;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/admin")
public class AdminDishController {

    @Autowired
    private DishInterface dishInterface;

    @PostMapping("/register-dish")
    public ResponseEntity<String> addDish(@RequestBody List<Dish> dishes) {
        return ResponseEntity.of(Optional.of(dishInterface.addDish(dishes)));
    }

    @PatchMapping("/change-dish-photo")
    public ResponseEntity<String> changeDishPhoto(@RequestPart String itemId, @RequestPart MultipartFile dishPhoto) throws UpdateFailedException, IOException {
        return ResponseEntity.of(Optional.of(dishInterface.changeDishPhoto(itemId, dishPhoto)));
    }

    @PutMapping("/edit-dish")
    public ResponseEntity<String> edit(@ModelAttribute Dish dish) throws UpdateFailedException {
        return ResponseEntity.of(Optional.of(dishInterface.editDish(dish)));
    }

    @DeleteMapping("/remove-dish")
    public ResponseEntity<String> removeDish(@RequestPart String itemId) throws UpdateFailedException {
        return ResponseEntity.of(Optional.of(dishInterface.removeDish(itemId)));
    }

    @DeleteMapping("/remove-dish-photo")
    public ResponseEntity<String> deleteOldPhoto(@RequestPart String itemId) throws IOException {
        return ResponseEntity.of(Optional.of(dishInterface.deleteDishPhoto(itemId)));
    }

}
