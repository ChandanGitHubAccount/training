package zomato.contoller.admincontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Categories;
import zomato.service.restaurant.CategoryInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/restaurant")
public class CategoriesController {

    /**
     * Category controller
     */

    @Autowired
    private CategoryInterface categoryInterface;

    @PostMapping("/register-categories")
    public ResponseEntity<String> addCategories(@RequestBody List<Categories> categories) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(categoryInterface.addCategories(categories)));
    }

    @PatchMapping("/change-delivery-charge")
    public ResponseEntity<String> changeDeliveryCharge(@RequestParam int deliveryCharge, @RequestParam String categoryName)
            throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(categoryInterface.changeDeliveryCharge(deliveryCharge, categoryName)));
    }

    @DeleteMapping("/remove-category")
    public ResponseEntity<String> removeCategory(@RequestParam String categoryName) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(categoryInterface.removeCategory(categoryName)));
    }

    @GetMapping("/details-categories")
    public ResponseEntity<List<Categories>> viewCategories() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(categoryInterface.viewCategories()));
    }

    @GetMapping("/particular-details")
    public ResponseEntity<Categories> viewCategory(@RequestParam String categoryName) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(categoryInterface.getParticularCategory(categoryName)));
    }

}
