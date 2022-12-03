package cric.champs.service.user;

import com.cloudinary.utils.ObjectUtils;
import cric.champs.customexceptions.*;
import cric.champs.entity.Tokens;
import cric.champs.entity.Users;
import cric.champs.security.userdetails.JWTUserDetailsService;
import cric.champs.security.utility.JWTUtility;
import cric.champs.service.AccountStatus;
import cric.champs.service.TokenStatus;
import cric.champs.service.cloud.UploadImageTOCloud;
import cric.champs.service.system.SystemInterface;
import cric.champs.service.system.TokenInterface;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class UserService implements LoginInterface {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private SystemInterface systemInterface;

    @Autowired
    private TokenInterface tokenInterface;

    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private JWTUserDetailsService jwtUserDetailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UploadImageTOCloud uploadImageTOCloud;

    /**
     * ******Login Interface******
     */

    @Override
    public Map<String, String> signIn(String email, String password) throws LoginFailedException {
        try {
            Map<String, String> result = new HashMap<>();
            List<Users> user = systemInterface.getUserDetails(email, AccountStatus.VERIFIED.toString());
            if (user.isEmpty())
                result.put("message", "Invalid credentials");
            else {
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
                final UserDetails userDetail = jwtUserDetailsService.loadUserByUsername(email);
                result.put("message", "login successful");
                result.put("username", email);
                result.put("token", jwtUtility.generateToken(userDetail));
            }
            return result;
        } catch (BadCredentialsException exception) {
            throw new LoginFailedException("Invalid credentials");
        }
    }

    @Override
    public Map<String, String> refreshToken(HttpServletRequest httpServletRequest) {
        DefaultClaims claims = (DefaultClaims) httpServletRequest.getAttribute("claims");
        Map<String, Object> expectedMap = systemInterface.getMapFromDefaultClaim(claims);
        String refreshToken = jwtUtility.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
        return Collections.singletonMap("refreshToken", refreshToken);
    }

    @SuppressWarnings("rawtypes")
    @Override
    public String signUp(Users user, MultipartFile profilePhoto) throws SignupException {
        try {
            Map result;
            if ((profilePhoto.isEmpty()))
                return "photo not uploaded.";
            else if (profilePhoto.isEmpty())
                return "photo not uploaded.";
            else
                result = uploadPhoto(profilePhoto);

            if (systemInterface.verifyEmail(user.getEmail())) {
                user.setProfilePicture(result.get("url").toString());
                return "Account successfully created";
            }
            return "Email or Phone number already registered";

        } catch (Exception exception) {
            throw new SignupException("Failed to register.Please provide valid details");
        }
    }

    @SuppressWarnings("rawtypes")
    private Map uploadPhoto(MultipartFile profilePhoto) throws IOException {
        return uploadImageTOCloud.uploadImage(profilePhoto.getBytes(), ObjectUtils.asMap("resource type", "auto"));
    }

    @Override
    public String forgotPassword(String email) throws UsernameNotFoundException {
        if (!systemInterface.verifyEmail(email)) {
            String token = tokenInterface.generate();
            if (!tokenInterface.verifyToken(token))
                forgotPassword(email);
            SimpleMailMessage emailContent = new SimpleMailMessage();
            emailContent.setFrom("raspberrypi001025@gmail.com");
            emailContent.setTo(systemInterface.getUserDetailByUserId().getEmail());
            emailContent.setSubject("Cric Champs Password Forgot Request");
            emailContent.setText("Click on below link to Reset password.");
            emailContent.setText("\nhttp://localhost:8080/reset-password/token=" + token);
            javaMailSender.send(emailContent);
            tokenInterface.save(token, email, LocalDateTime.now(), LocalDateTime.now().plusMinutes(30L), TokenStatus.ACTIVE.toString());
            return "If the mail address entered matches your account , you will receive an email with a link to reset your password";
        }
        throw new UsernameNotFoundException("username not found");
    }

    @Override
    public String resetPassword(String token, String newPassword, String confirmPassword) throws TokenExpiredException {
        List<Tokens> tokens = tokenInterface.getTokenDetail(token);
        if (!tokens.isEmpty()) {
            if (newPassword.equals(confirmPassword)) {
                if (tokens.get(0).getExpireAt().compareTo(LocalDateTime.now()) >= 0) {
                    jdbcTemplate.update("update users set password = ? where username = ? and is_deleted = 'false' ", newPassword, tokens.get(0).getUserId());
                    tokenInterface.remove(token, tokens.get(0).getUserId());
                    return "Password updated successfully";
                }
                throw new TokenExpiredException("token expired");
            }
            return "password not matched";
        }
        throw new TokenExpiredException("token already used");
    }

    @Override
    public String changePassword(String newPassword, String confirmPassword) {
        try {
            if (newPassword.equals(confirmPassword)) {
                jdbcTemplate.update("update users set password = ? where user_id = ? and is_deleted = 'false'",
                        passwordEncoder.encode(newPassword), systemInterface.getUserId());
                return "Password updated successfully";
            }
            throw new Exception("password miss matched");
        } catch (Exception exception) {
            throw new NullPointerException("login to perform action");
        }
    }

    @Override
    @SuppressWarnings("rawtypes")
    public String changeProfilePhoto(MultipartFile profilePhoto) throws IOException, UpdateFailedException {
        Map result = null;
        if ((profilePhoto.isEmpty()))
            throw new UpdateFailedException("Profile photo uploading failed");
        else if (profilePhoto.isEmpty())
            throw new UpdateFailedException("Profile photo uploading failed");
        else {
            result = uploadPhoto(profilePhoto);
            jdbcTemplate.update("update users set profile_photo = ? where user_id = ? and is_deleted = 'false'",
                    result.get("url").toString(), systemInterface.getUserId());
            return "Profile photo uploaded successfully";
        }
    }

    @Override
    public String deleteOldProfilePhoto() {
        Users user = systemInterface.getUserDetailByUserId();
        if (user.getProfilePicture() != null) {
            jdbcTemplate.update("update users set profile_photo = ? where user_id = ? and is_deleted = 'false'",
                    null, systemInterface.getUserId());
            return "photo deleted successfully";
        }
        throw new NullPointerException("Photo not uploaded");
    }

}
