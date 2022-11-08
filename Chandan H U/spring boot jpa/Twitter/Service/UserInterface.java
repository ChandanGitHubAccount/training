package Twitter.Service;

import Twitter.Model.TwitterUsers;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface UserInterface {
    TwitterUsers signup(TwitterUsers twitterUser);

    String signIn(int userId, String password);

    String changeProfilePicture(MultipartFile file);

    List<AccountType> viewAvailableAccountTypes();

    List<GenderAvailable> viewAvailableGenders();
}
