package cric.champs.service.user;

import cric.champs.customexceptions.*;
import cric.champs.entity.Users;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;

public interface LoginInterface {

    Map<String, String> signIn(String userName, String password) throws LoginFailedException;

    Map<String, String> refreshToken(HttpServletRequest httpServletRequest);

    String signUp(Users user, MultipartFile file) throws SignupException, UsernameNotFoundException, IOException;

    String forgotPassword(String username) throws UsernameNotFoundException;

    String resetPassword(String token, String newPassword, String confirmPassword) throws TokenExpiredException;

    String changePassword(String newPassword, String confirmPassword) throws Exception;

    String changeProfilePhoto(MultipartFile file) throws IOException, UpdateFailedException;

    String deleteOldProfilePhoto();

}
