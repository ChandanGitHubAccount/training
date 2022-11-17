package zomato.service.user;

import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.*;
import zomato.entity.Users;

import java.io.IOException;

public interface LoginInterface {
    String signIn(String userName, String password) throws LoginFailedException, SessionIdExpiredException;

    String signUp(Users user , MultipartFile file) throws SignupException, SessionIdExpiredException, UsernameNotFoundException;

    String signOut() throws SignOutException, SessionIdExpiredException;

    String forgotPassword(String username) throws UsernameNotFoundException, SessionIdExpiredException;

    String changePassword(String newPassword, String confirmPassword) throws SessionIdExpiredException;

    String resetPassword(String token, String newPassword, String confirmPassword) throws SessionIdExpiredException, TokenExpiredException;

    String changeProfilePhoto(MultipartFile file) throws IOException, SessionIdExpiredException;

    byte[] viewProfilePhoto() throws SessionIdExpiredException, IOException;

    String deleteOldProfilePhoto() throws SessionIdExpiredException, IOException;
}
