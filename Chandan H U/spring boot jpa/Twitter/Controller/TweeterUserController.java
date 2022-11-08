package Twitter.Controller;

import Twitter.Model.TwitterUsers;
import Twitter.Service.AccountType;
import Twitter.Service.GenderAvailable;
import Twitter.Service.UserInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class TweeterUserController {
    @Autowired
    private UserInterface userInterface;

    @PostMapping("/sign-up")
    ResponseEntity<TwitterUsers> signUp(@RequestBody TwitterUsers twitterUser) {
        try {
            return ResponseEntity.of(Optional.of(userInterface.signup(twitterUser)));
        } catch (Exception exception) {
            exception.printStackTrace();
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @PostMapping("/sign-in")
    ResponseEntity<String> signIn(@RequestParam("userId") int userId, @RequestParam("password") String password) {
        try {
            return ResponseEntity.of(Optional.of(userInterface.signIn(userId, password)));
        } catch (Exception exception) {
            exception.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @PutMapping("/change-profile-pic")
    ResponseEntity<String> changeProfilePic(@RequestParam("picFile") MultipartFile picFile) {
        try {
            return ResponseEntity.of(Optional.of(userInterface.changeProfilePicture(picFile)));
        } catch (Exception exception) {
            exception.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/available-account-type")
    ResponseEntity<List<AccountType>> availableAccountTypes() {
        try {
            return ResponseEntity.of(Optional.of(userInterface.viewAvailableAccountTypes()));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/available-gender")
    ResponseEntity<List<GenderAvailable>> availableGender(){
        try {
            return ResponseEntity.of(Optional.of(userInterface.viewAvailableGenders()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

}
