package Twitter.Service;

import Twitter.Model.TwitterUsers;
import Twitter.Repository.TwitterUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

@Service
public class TwitterUserService implements UserInterface {
    @Autowired
    private TwitterUserRepository twitterUserRepository;

    private int loggedInUser;

    private static final String filePath = "C:\\Users\\Chandan H U\\Desktop\\TwitterProfilePics";

    @Override
    public TwitterUsers signup(TwitterUsers twitterUser) {
        try {
            twitterUserRepository.save(twitterUser);
            return twitterUser;
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public String signIn(int userId, String password) {
        try {
            List<TwitterUsers> twitterUsers = twitterUserRepository.findByUserIdAndUserPassword(userId, password);
            if (twitterUsers.isEmpty())
                return "Invalid UserId/Password ";
            else {
                loggedInUser = userId;
                return "Login Successful";
            }
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public String changeProfilePicture(MultipartFile file) {
        try {
            String profilePhotoPath = filePath + File.separator + file.getOriginalFilename();
            file.transferTo(new File(profilePhotoPath));
            twitterUserRepository.changeProfilePhoto(profilePhotoPath, loggedInUser);
            return "Profile Picture Changed.";
        } catch (IOException ioException) {
            ioException.printStackTrace();
            return "Unable To Change Profile Picture.";
        }
    }

    @Override
    public List<AccountType> viewAvailableAccountTypes() {
        try {
            return new ArrayList<>(EnumSet.allOf(AccountType.class));
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<GenderAvailable> viewAvailableGenders() {
        try {
            return new ArrayList<>(EnumSet.allOf(GenderAvailable.class));
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }

}
