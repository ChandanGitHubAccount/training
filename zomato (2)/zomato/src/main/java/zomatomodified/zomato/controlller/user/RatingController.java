package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.model.Restaurants;
import zomatomodified.zomato.service.user.RatingInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user/rating-favourites")
public class RatingController {

    /**
     * ******Rating Controller******
     */

    @Autowired
    private RatingInterface ratingInterface;

    @PostMapping("/add-favourites")
    public ResponseEntity<String> addToFavourites(@RequestPart String restaurantId)   {
        return ResponseEntity.of(Optional.of(ratingInterface.addToFavourite(restaurantId)));
    }

    @PatchMapping("/rate-restaurant")
    public ResponseEntity<String> rateRestaurant(@RequestPart String orderId)   {
        ratingInterface.rating(orderId);
        return ResponseEntity.ok("thank you for rating");
    }

    @GetMapping("/view-favourites")
    public ResponseEntity<List<Restaurants>> viewFavourites()   {
        return ResponseEntity.of(Optional.of(ratingInterface.viewFavorites()));
    }

}