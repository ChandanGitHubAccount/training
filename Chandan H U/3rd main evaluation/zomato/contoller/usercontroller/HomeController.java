package zomato.contoller.usercontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.entity.Restaurants;
import zomato.model.Categories;
import zomato.service.user.HomeInterface;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user/home")
public class HomeController {

    /**
     * ******Home Controller******
     */

    @Autowired
    private HomeInterface homeInterface;

    @GetMapping("/view-restaurant")
    public ResponseEntity<Page<Restaurants>> viewRestaurants(@RequestParam int pageNumber, @RequestParam int pageSize) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(homeInterface.topRatedRestaurants(pageNumber, pageSize)));
    }

    @GetMapping("/view-categories")
    public ResponseEntity<List<Categories>> viewCategories(@RequestParam int pageNumber,@RequestParam int pageSize) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(homeInterface.viewCategories(pageNumber, pageSize)));
    }

    @GetMapping("/view-restaurant-photo")
    public ResponseEntity<?> viewRestaurantPhoto(@RequestParam String restaurantId) throws SessionIdExpiredException, IOException {
        byte[] image = homeInterface.viewRestaurantPhoto(restaurantId);
        return ResponseEntity.ok().contentType(MediaType.valueOf("image/png")).body(image);
    }

}
