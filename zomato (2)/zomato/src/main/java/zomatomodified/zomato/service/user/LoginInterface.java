package zomatomodified.zomato.service.user;

import org.springframework.web.multipart.MultipartFile;
import zomatomodified.zomato.coustomexcptions.*;
import zomatomodified.zomato.entity.Users;

import java.io.IOException;

public interface LoginInterface {

    String signIn(String userName, String password) throws LoginFailedException, SessionIdExpiredException;

    String signUp(Users user, MultipartFile file) throws SignupException, SessionIdExpiredException, UsernameNotFoundException, IOException;

    String forgotPassword(String username) throws UsernameNotFoundException, SessionIdExpiredException;

    String signOut() throws SignOutException;

    String resetPassword(String token, String newPassword, String confirmPassword) throws SessionIdExpiredException, TokenExpiredException;

    String changePassword(String newPassword, String confirmPassword) throws Exception;

    String changeProfilePhoto(MultipartFile file) throws IOException, UpdateFailedException;

    byte[] viewProfilePhoto() throws IOException;

    String deleteOldProfilePhoto() throws IOException;
}
