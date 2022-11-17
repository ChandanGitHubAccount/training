package zomato.contoller.usercontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.*;
import zomato.entity.Users;
import zomato.service.user.LoginInterface;
import zomato.service.user.SystemInterface;

import javax.validation.Valid;
import java.io.IOException;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class UserLoginController {

    @Autowired
    private LoginInterface loginInterface;

    @Autowired
    private SystemInterface systemInterface;

    /**
     * ******Login Controller******
     */

    @PostMapping("/sign-in")
    public ResponseEntity<String> userLogin(@RequestParam String username, @RequestParam String password) throws LoginFailedException, SessionIdExpiredException {
        if (username != null && (password != null))
            return ResponseEntity.of(Optional.of(loginInterface.signIn(username, password)));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authorization failed.");
    }

    @PostMapping("/sign-up")
    public ResponseEntity<String> newRegistration(@ModelAttribute @Valid Users user, @RequestParam MultipartFile file) throws SignupException, SessionIdExpiredException, UsernameNotFoundException {
        if (user != null)
            return ResponseEntity.of(Optional.of(loginInterface.signUp(user, file)));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Provide valid details for registration");
    }

    @DeleteMapping("/sign-out")
    public ResponseEntity<String> logOut() throws SignOutException, SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(loginInterface.signOut()));
    }

    @PatchMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestParam String newPassword, @RequestParam String confirmPassword) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(loginInterface.changePassword(newPassword, confirmPassword)));
    }

    @PatchMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam String email) throws UsernameNotFoundException, SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(loginInterface.forgotPassword(email)));
    }

    @PatchMapping("/reset-password/token={token}")
    public ResponseEntity<String> resetPassword(@PathVariable String token, @RequestParam String newPassword,
                                                @RequestParam String confirmPassword) throws SessionIdExpiredException, TokenExpiredException {
        return ResponseEntity.of(Optional.of(loginInterface.resetPassword(token, newPassword, confirmPassword)));
    }

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp() throws Exception {
        return ResponseEntity.of(Optional.of(systemInterface.sendOTP()));
    }

    @PatchMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam int otp) throws Exception {
        return ResponseEntity.of(Optional.of(systemInterface.verifyEmail(otp)));
    }

    @PatchMapping("/change-profile-photo")
    public ResponseEntity<String> changeProfilePhoto(@RequestParam MultipartFile file) throws SessionIdExpiredException, IOException {
        return ResponseEntity.of(Optional.of(loginInterface.changeProfilePhoto(file)));
    }

    @GetMapping("/view-profile-photo")
    public ResponseEntity<?> viewProfilePhoto() throws SessionIdExpiredException, IOException {
        byte[] image = loginInterface.viewProfilePhoto();
        return ResponseEntity.ok().contentType(MediaType.valueOf("image/png")).body(image);
    }

    @DeleteMapping("/remove-profile-photo")
    public ResponseEntity<String> removeProfilePhoto() throws SessionIdExpiredException, IOException {
        return ResponseEntity.of(Optional.of(loginInterface.deleteOldProfilePhoto()));
    }
}
