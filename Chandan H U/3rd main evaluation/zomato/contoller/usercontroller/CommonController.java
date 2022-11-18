package zomato.contoller.usercontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Categories;
import zomato.model.Menu;
import zomato.service.user.CategoriesInterface;
import zomato.service.user.MenuInterface;
import zomato.service.user.SearchInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user/find")
public class CommonController {

    /**
     * ******Common Controller For Home Page And Filter Page******
     */

    @Autowired
    private MenuInterface menuInterface;

    @Autowired
    private CategoriesInterface categoriesInterface;

    @Autowired
    private SearchInterface searchInterface;

    @GetMapping("/view-menu")
    public ResponseEntity<List<Menu>> viewAllMenu(@RequestParam String categoryName, @RequestParam int pageSize,
                                                  @RequestParam int pageNumber) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(menuInterface.viewMenuOfCategory(categoryName, pageSize, pageNumber)));
    }

    @GetMapping("/view-Restaurant-categories")
    public ResponseEntity<List<Categories>> showAllCategoriesOfRestaurant(@RequestParam String restaurantId, @RequestParam int pageSize,
                                                                          @RequestParam int pageNumber) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(categoriesInterface.showAllCategoriesOfRestaurant(restaurantId, pageSize, pageNumber)));
    }

    @GetMapping("/view-restaurant-menu")
    public ResponseEntity<List<Menu>> viewMenuOfRestaurant(@RequestParam String restaurantId, @RequestParam String categoryName,
                                                           @RequestParam int pageSize, @RequestParam int pageNumber) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(menuInterface.viewMenuOfRestaurant(restaurantId, categoryName, pageSize, pageNumber)));
    }

    @GetMapping("/search")
    public ResponseEntity<?> searchField(@RequestParam String field) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(searchInterface.search(field)));
    }

}
