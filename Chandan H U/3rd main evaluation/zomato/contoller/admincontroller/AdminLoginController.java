package zomato.contoller.admincontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.service.restaurant.RestaurantInterface;

import javax.validation.Valid;
import java.io.IOException;
import java.time.LocalTime;
import java.util.Optional;

@RestController
@RequestMapping("/restaurant")
public class AdminLoginController {

    /**
     * Restaurant controller
     */

    @Autowired
    private RestaurantInterface restaurantInterface;

    @PostMapping("/sign-up")
    public ResponseEntity<String> newRegistration(@RequestParam String restaurantId, @RequestParam @Valid String restaurantName,
                                                  @RequestParam @Valid String restaurantAddress, @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime openAt,
                                                  @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.TIME) LocalTime closeAt, @RequestParam @Valid String closeOn,
                                                  @RequestParam(required = false) MultipartFile restaurantPhoto) throws SessionIdExpiredException, IOException {
        return ResponseEntity.of(Optional.of(restaurantInterface.register(restaurantId, restaurantName, restaurantAddress, openAt, closeAt, closeOn, restaurantPhoto)));
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String restaurantId) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantInterface.Login(restaurantId)));
    }

    @DeleteMapping("/logout")
    public ResponseEntity<String> logout() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantInterface.logout()));
    }
}
