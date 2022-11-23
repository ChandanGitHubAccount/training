package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.entity.Categories;
import zomatomodified.zomato.model.Restaurants;
import zomatomodified.zomato.service.user.CategoriesInterface;
import zomatomodified.zomato.service.user.HomeInterface;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class HomeController {

    /**
     * ******Home Controller******
     */

    @Autowired
    private HomeInterface homeInterface;

    @Autowired
    private CategoriesInterface categoriesInterface;

    @GetMapping("/view-categories-restaurant")
    public ResponseEntity<List<Categories>> viewCategoriesRestaurants(@RequestHeader String restaurantId,@RequestParam int pageNumber, @RequestParam int pageSize)   {
        return ResponseEntity.of(Optional.of(categoriesInterface.showAllCategoriesOfRestaurant(restaurantId,pageSize,pageNumber)));
    }

    @GetMapping("/view-restaurant")
    public ResponseEntity<List<Restaurants>> viewRestaurants(@RequestParam int pageNumber, @RequestParam int pageSize)   {
        return ResponseEntity.of(Optional.of(homeInterface.topRatedRestaurants(pageNumber, pageSize)));
    }

    @GetMapping("/view-categories")
    public ResponseEntity<List<Categories>> viewCategories(@RequestParam int pageNumber, @RequestParam int pageSize)   {
        return ResponseEntity.of(Optional.of(homeInterface.viewCategories(pageNumber, pageSize)));
    }

    @GetMapping("/view-restaurant-photo")
    public ResponseEntity<?> viewRestaurantPhoto(@RequestHeader String restaurantId) throws  IOException {
        byte[] image = homeInterface.viewRestaurantPhoto(restaurantId);
        return ResponseEntity.ok().contentType(MediaType.valueOf("image/png")).body(image);
    }

}
