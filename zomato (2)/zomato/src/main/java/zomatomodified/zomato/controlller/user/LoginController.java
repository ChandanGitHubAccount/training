package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import zomatomodified.zomato.coustomexcptions.*;
import zomatomodified.zomato.entity.Users;
import zomatomodified.zomato.service.system.SystemInterface;
import zomatomodified.zomato.service.user.LoginInterface;

import javax.validation.Valid;
import java.io.IOException;
import java.util.Optional;

@RestController
public class LoginController {

    @Autowired
    private LoginInterface loginInterface;

    @Autowired
    private SystemInterface systemInterface;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<String> userLogin(@RequestHeader String username, @RequestHeader String password) throws LoginFailedException, SessionIdExpiredException {
        if (username != null && (password != null))
            return ResponseEntity.of(Optional.of(loginInterface.signIn(username, password)));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authorization failed.");
    }

    @PostMapping("/sign-up")
    public ResponseEntity<String> newRegistration(@ModelAttribute @Valid Users user, @RequestPart MultipartFile profilePhotos) throws SignupException, SessionIdExpiredException, UsernameNotFoundException, IOException {
        if (user != null)
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        return ResponseEntity.of(Optional.of(loginInterface.signUp(user, profilePhotos)));
    }

    @DeleteMapping("/sign-out")
    public ResponseEntity<String> logOut() throws SignOutException {
        return ResponseEntity.of(Optional.of(loginInterface.signOut()));
    }

    @PatchMapping("/user/change-password")
    public ResponseEntity<String> changePassword(@RequestHeader String newPassword, @RequestHeader String confirmPassword) throws Exception {
        return ResponseEntity.of(Optional.of(loginInterface.changePassword(newPassword, confirmPassword)));
    }

    @PatchMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestHeader String email) throws SessionIdExpiredException, UsernameNotFoundException {
        return ResponseEntity.of(Optional.of(loginInterface.forgotPassword(email)));
    }

    @PatchMapping("/reset-password/token={token}")
    public ResponseEntity<String> resetPassword(@PathVariable String token, @RequestHeader String newPassword,
                                                @RequestHeader String confirmPassword) throws TokenExpiredException, SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(loginInterface.resetPassword(token, newPassword, confirmPassword)));
    }

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestHeader String email) throws Exception {
        return ResponseEntity.of(Optional.of(systemInterface.sendOTP(email)));
    }

    @PatchMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestParam int otp, @RequestHeader String email) throws Exception {
        return ResponseEntity.of(Optional.of(systemInterface.verifyEmail(otp, email)));
    }

    @PatchMapping("/user/change-profile-photo")
    public ResponseEntity<String> changeProfilePhoto(@RequestParam MultipartFile profilePhoto) throws IOException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(loginInterface.changeProfilePhoto(profilePhoto)));
    }

    @GetMapping("/user/view-profile-photo")
    public ResponseEntity<?> viewProfilePhoto() throws IOException {
        byte[] image = loginInterface.viewProfilePhoto();
        return ResponseEntity.ok().contentType(MediaType.valueOf("image/png")).body(image);
    }

    @DeleteMapping("/user/remove-profile-photo")
    public ResponseEntity<String> removeProfilePhoto() throws IOException {
        return ResponseEntity.of(Optional.of(loginInterface.deleteOldProfilePhoto()));
    }

}
