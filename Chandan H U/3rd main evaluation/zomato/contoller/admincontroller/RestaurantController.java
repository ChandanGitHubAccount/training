package zomato.contoller.admincontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.InvalidTimeException;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.coustomexcptions.UpdateFailedException;
import zomato.entity.Restaurants;
import zomato.service.restaurant.RestaurantInterface;

import java.io.IOException;
import java.util.Optional;

@RestController
@RequestMapping("/restaurant")
public class RestaurantController {

    /**
     * Restaurant controller
     */

    @Autowired
    private RestaurantInterface restaurantInterface;

    @GetMapping("/details")
    public ResponseEntity<Restaurants> viewDetails() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantInterface.viewRestaurantDetails()));
    }

    @GetMapping("/photo")
    public ResponseEntity<?> viewPhoto() throws SessionIdExpiredException, IOException {
        byte[] image = restaurantInterface.viewRestaurantPhoto();
        return ResponseEntity.ok().contentType(MediaType.valueOf("image/png")).body(image);
    }

    @PatchMapping("/change-restaurant-photo")
    public ResponseEntity<String> changeRestaurantPhoto(@RequestParam MultipartFile restaurantPhoto)
            throws SessionIdExpiredException, IOException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(restaurantInterface.changeRestaurantPhoto(restaurantPhoto)));
    }

    @PatchMapping("/change-open-time")
    public ResponseEntity<String> changeOpenTime(@RequestParam int openHour, @RequestParam int openMinutes)
            throws InvalidTimeException, SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantInterface.changeOpenTime(openHour, openMinutes)));
    }

    @PatchMapping("/change-close-time")
    public ResponseEntity<String> changeCloseTime(@RequestParam int closeHour, @RequestParam int closeMinutes)
            throws InvalidTimeException, SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantInterface.changeCloseTime(closeHour, closeMinutes)));
    }

    @PatchMapping("/change-close-day")
    public ResponseEntity<String> changeCloseDay(@RequestParam String day) throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(restaurantInterface.changeCloseDay(day.toUpperCase())));
    }

    @PatchMapping("/change-restaurant-address")
    public ResponseEntity<String> changeRestaurantAddress(@RequestParam String restaurantAddress)
            throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(restaurantInterface.changeRestaurantAddress(restaurantAddress)));
    }

    @PatchMapping("/change-restaurant-name")
    public ResponseEntity<String> changeRestaurantName(@RequestParam String restaurantName)
            throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(restaurantInterface.changeRestaurantName(restaurantName)));
    }

    @DeleteMapping("/remove-restaurant-photo")
    public ResponseEntity<String> deleteRestaurantPhoto() throws SessionIdExpiredException, IOException {
        return ResponseEntity.of(Optional.of(restaurantInterface.deleteRestaurantPhoto()));
    }

    @DeleteMapping("/remove-restaurant")
    public ResponseEntity<String> deleteRestaurant() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantInterface.deleteRestaurant()));
    }

}
