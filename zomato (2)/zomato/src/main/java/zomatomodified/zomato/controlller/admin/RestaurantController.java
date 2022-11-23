package zomatomodified.zomato.controlller.admin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import zomatomodified.zomato.coustomexcptions.UpdateFailedException;
import zomatomodified.zomato.model.Restaurants;
import zomatomodified.zomato.service.admin.RestaurantInterface;

import javax.validation.Valid;
import java.io.IOException;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/admin")
public class RestaurantController {

    @Autowired
    private RestaurantInterface restaurantInterface;

    @PostMapping("/register")
    public ResponseEntity<String> newRegistration(@RequestParam String restaurantName, @RequestParam String restaurantAddress, @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime openAt,
                                                  @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime closeAt, @RequestParam @Valid String closeOn,
                                                  @RequestParam int deliveryCharge, @RequestParam MultipartFile restaurantPhoto) throws IOException {
        return ResponseEntity.of(Optional.of(restaurantInterface.register(restaurantName, restaurantAddress, openAt, closeAt, closeOn, deliveryCharge, restaurantPhoto)));
    }

    @GetMapping("/view")
    public ResponseEntity<List<Restaurants>> viewAll() {
        return ResponseEntity.of(Optional.of(restaurantInterface.viewRestaurantDetails()));
    }

    @GetMapping("/photo")
    public ResponseEntity<?> viewPhoto(@RequestBody String restaurantId) throws IOException {
        byte[] image = restaurantInterface.viewRestaurantPhoto(restaurantId);
        return ResponseEntity.ok().contentType(MediaType.valueOf("image/png")).body(image);
    }

    @PatchMapping("/change-restaurant-photo")
    public ResponseEntity<String> changeRestaurantPhoto(@RequestBody String restaurantId, @RequestBody MultipartFile restaurantPhoto)
            throws IOException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(restaurantInterface.changeRestaurantPhoto(restaurantId, restaurantPhoto)));
    }

    @DeleteMapping("/remove-restaurant-photo")
    public ResponseEntity<String> deleteRestaurantPhoto(@RequestBody String restaurantId) throws IOException {
        return ResponseEntity.of(Optional.of(restaurantInterface.deleteRestaurantPhoto(restaurantId)));
    }

    @DeleteMapping("/remove-restaurant")
    public ResponseEntity<String> deleteRestaurant(@RequestBody String restaurantId) {
        return ResponseEntity.of(Optional.of(restaurantInterface.deleteRestaurant(restaurantId)));
    }

    @PutMapping("/edit")
    public ResponseEntity<String> edit(@RequestBody Restaurants restaurant) {
        return ResponseEntity.of(Optional.of(restaurantInterface.editRestaurant(restaurant)));
    }

    @GetMapping("/view-restaurant")
    public ResponseEntity<Restaurants> viewRestaurant(@RequestBody String restaurantId) throws IOException {
        return ResponseEntity.of(Optional.of(restaurantInterface.viewParticularRestaurantDetails(restaurantId)));
    }
}
