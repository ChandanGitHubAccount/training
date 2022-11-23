package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.model.Dish;
import zomatomodified.zomato.service.user.DishInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class DishController {

    @Autowired
    private DishInterface dishInterface;

    @GetMapping("/viewDishOfRestaurant")
    public ResponseEntity<List<Dish>> viewDishOfRestaurant(@RequestPart String restaurantId, @RequestParam int pageSize, @RequestParam int pageNumber){
        return ResponseEntity.of(Optional.of(dishInterface.viewDishOfRestaurant(restaurantId,pageSize,pageNumber)));
    }

    @GetMapping("/viewDishOfCategory")
    public ResponseEntity<List<Dish>> viewDishOfCategory(@RequestPart String categoryId, @RequestParam int pageSize, @RequestParam int pageNumber){
        return ResponseEntity.of(Optional.of(dishInterface.viewDishOfCategory(categoryId,pageSize,pageNumber)));
    }

    @GetMapping("/getDishDetails-of-category-of-restaurant")
    public ResponseEntity<Dish> getDishDetails(@RequestPart String itemId){
        return ResponseEntity.of(Optional.of(dishInterface.getDishDetails(itemId)));
    }

}
