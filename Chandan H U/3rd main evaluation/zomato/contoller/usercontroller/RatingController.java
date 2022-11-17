package zomato.contoller.usercontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Favourite;
import zomato.service.user.RatingInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class RatingController {

    /**
     * ******Rating Controller******
     */

    @Autowired
    private RatingInterface ratingInterface;

    @PostMapping("/add-favourites")
    public ResponseEntity<String> addToFavourites(@RequestParam String restaurantName) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(ratingInterface.addToFavourite(restaurantName)));
    }

    @PatchMapping("/rate-restaurant")
    public ResponseEntity<String> rateRestaurant(@RequestParam String orderId) throws SessionIdExpiredException {
        ratingInterface.rating(orderId);
        return ResponseEntity.ok("thank you for rating");
    }

    @GetMapping("/view-favourites")
    public ResponseEntity<List<Favourite>> viewFavourites() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(ratingInterface.viewFavorites()));
    }

    @DeleteMapping("/remove-favourites")
    public ResponseEntity<String> removeFavourites(@RequestParam String restaurantName) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(ratingInterface.deleteFavourite(restaurantName)));
    }
}
