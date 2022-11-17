package zomato.service.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.*;
import zomato.entity.Restaurants;
import zomato.entity.Users;
import zomato.model.*;
import zomato.repositatory.RestaurantRepository;
import zomato.repositatory.UserRepository;
import zomato.service.AccountStatus;
import zomato.service.OrderStatus;
import zomato.service.PaymentTypes;
import zomato.service.TokenStatus;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class UserServiceImplementation implements LoginInterface, SystemInterface, HomeInterface, FilterInterface, CategoriesInterface, MenuInterface, CardInterface, OrderInterface, RatingInterface, SearchInterface {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private TokenInterface tokenInterface;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RestaurantRepository restaurantRepository;

    private static final String userProfileFilePath = "C:\\Users\\Chandan H U\\Desktop\\userProfilePhoto";

    private String sessionId;

    private Users loggedUser;

    /**
     * ******Login Interface******
     */

    protected String generateSessionId() {
        return Integer.toString(new Random().nextInt(1000, 10000));
    }

    @Override
    public String signIn(String email, String password) throws LoginFailedException, SessionIdExpiredException {
        try {
            if (sessionId == null) {
                List<Users> user = userRepository.findByEmailAndPassword(email, password);
                if (user.isEmpty())
                    return "Invalid email or password";
                if (user.get(0).getAccountStatus().equalsIgnoreCase(AccountStatus.NOTVERIFIED.toString()))
                    return "verify the email before login";
                this.loggedUser = user.get(0);
                this.sessionId = generateSessionId();
                return "Login Successful with Session Id : " + sessionId;
            }
            throw new SessionIdExpiredException("you are already logged in. please logout for new sign in");

        } catch (DataAccessException exception) {
            throw new LoginFailedException("Failed login");
        }
    }

    @Override
    public String signUp(Users user, MultipartFile profilePhoto) throws SignupException, SessionIdExpiredException {
        try {
            if (sessionId == null) {
                String userId = generateId();
                if (userRepository.findById(userId).isPresent())
                    signUp(user, profilePhoto);
                user.setAccountStatus(AccountStatus.NOTVERIFIED.toString());
                if (profilePhoto.getOriginalFilename() != null) {
                    user.setProfilePhoto(userProfileFilePath + File.separator + profilePhoto.getOriginalFilename());
                    profilePhoto.transferTo(Path.of(userProfileFilePath + File.separator + profilePhoto.getOriginalFilename()));
                } else user.setProfilePhoto(null);
                if (checkForDuplicateRegistration(user.getEmail(), user.getPhoneNumber())) {
                    userRepository.save(user);
                    return "Account successfully created";
                }
                return "Email or Phone number already registered";
            }
            throw new SessionIdExpiredException("Please logout before signup");
        } catch (DataAccessException | IOException exception) {
            throw new SignupException("Failed to register.Please provide valid details");
        }
    }

    @Override
    public String signOut() throws SignOutException {
        try {
            if (sessionId != null) {
                this.loggedUser = null;
                this.sessionId = null;
                return "sign out successful";
            }
            throw new SessionIdExpiredException("Login before sign out.");
        } catch (Exception exception) {
            throw new SignOutException("sign out failed.try again after sometime.");
        }
    }

    @Override
    public String forgotPassword(String email) throws UsernameNotFoundException, SessionIdExpiredException {
        if (sessionId == null) {
            if (!checkAvailabilityOfEmail(email)) {
                String token = tokenInterface.generate();
                if (!verifyToken(token))
                    forgotPassword(email);

                SimpleMailMessage emailContent = new SimpleMailMessage();
                emailContent.setFrom("raspberrypi001025@gmail.com");
                emailContent.setTo(loggedUser.getEmail());
                emailContent.setSubject("Password Forgot Request");
                emailContent.setText("Click on below link to Reset password.");
                emailContent.setText("\nhttp://localhost:8080/reset-password/token=" + token);
                javaMailSender.send(emailContent);
                tokenInterface.save(token, email, LocalDateTime.now(), LocalDateTime.now().plusMinutes(30L), TokenStatus.ACTIVE.toString());
                return "If the mail address entered matches your account , you will receive an email with a link to reset your password";
            }
            throw new UsernameNotFoundException("username not found");
        }
        throw new SessionIdExpiredException("You already logged in");
    }

    @Override
    public String changePassword(String newPassword, String confirmPassword) throws SessionIdExpiredException {
        if (sessionId != null)
            return updatePassword(newPassword, confirmPassword);
        throw new SessionIdExpiredException("Login before changing password");
    }

    @Override
    public String resetPassword(String token, String newPassword, String confirmPassword) throws SessionIdExpiredException, TokenExpiredException {
        List<Tokens> tokens = tokenInterface.getTokenDetail(token);
        if (!tokens.isEmpty()) {
            if (newPassword.equals(confirmPassword)) {
                if (tokens.get(0).getExpireAt().compareTo(LocalDateTime.now()) >= 0) {
                    jdbcTemplate.update("update user set password = ? where username = ? ", newPassword, tokens.get(0).getUserId());
                    tokenInterface.remove(token, tokens.get(0).getUserId());
                    return "Password updated successfully";
                }
                throw new TokenExpiredException("token expired");
            }
            return "password not matched";
        }
        throw new SessionIdExpiredException("token already used");
    }

    @Override
    public String changeProfilePhoto(MultipartFile file) throws IOException, SessionIdExpiredException {
        checkSession();

        if (file.getOriginalFilename() != null) {
            deleteOldProfilePhoto();
            String setProfilePhoto = userProfileFilePath + File.separator + file.getOriginalFilename();
            jdbcTemplate.update("update users set profile_photo = ? ", setProfilePhoto);
            file.transferTo(Path.of(setProfilePhoto));
            return "Profile photo uploaded successfully";
        } else
            return "Profile photo uploading failed";

    }

    @Override
    public byte[] viewProfilePhoto() throws SessionIdExpiredException, IOException {
        checkSession();

        Users user = userRepository.findByUserId(loggedUser.getUserId()).get(0);
        if (user.getProfilePhoto() != null) {
            String photo = user.getProfilePhoto();
            return Files.readAllBytes(Path.of(photo));
        }
        throw new NullPointerException("Photo not uploaded");

    }

    @Override
    public String deleteOldProfilePhoto() throws SessionIdExpiredException, IOException {
        checkSession();
        Users user = userRepository.findByUserId(loggedUser.getUserId()).get(0);
        if (user.getProfilePhoto() != null) {
            String photo = user.getProfilePhoto();
            Files.deleteIfExists(Path.of(photo));
            jdbcTemplate.update("update users set profile_photo = ? where user_id = ?", null, loggedUser.getUserId());
            return "photo deleted successfully";
        }
        throw new NullPointerException("Photo not uploaded");

    }

    /**
     * ******System private methods******
     */

    private boolean verifyToken(String token) {
        return jdbcTemplate.query("Select * from tokens where secureToken = ?", new BeanPropertyRowMapper<>(Tokens.class), token).isEmpty();
    }

    private boolean checkAvailabilityOfEmail(String email) {
        return userRepository.findByEmail(email).isEmpty();
    }

    private boolean checkForDuplicateRegistration(String email, long phoneNumber) {
        return userRepository.findByEmailOrPhoneNumber(email, phoneNumber).isEmpty();
    }

    private String updatePassword(String newPassword, String confirmPassword) throws SessionIdExpiredException {
        if (newPassword.equals(confirmPassword)) {
            jdbcTemplate.update("update user set password = ?", newPassword);
            return "Password updated successfully";
        }
        throw new SessionIdExpiredException("token expired");
    }


    /**
     * ******System Interface******
     */

    @Override
    public String generateId() {
        Random random = new Random();
        StringBuilder userId = new StringBuilder();
        for (int index = 0; index < 4; index++) {
            char character = (char) (65 + random.nextInt(26));
            try {
                userId.append(character);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        for (int index = 0; index < 6; index++) {
            char number = (char) (48 + random.nextInt(10));
            try {
                userId.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return userId.toString();
    }

    @Override
    public int generateOTP() {
        Random random = new Random();
        StringBuilder otp = new StringBuilder();
        for (int index = 0; index < 6; index++) {
            char number = (char) (48 + random.nextInt(10));
            try {
                otp.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return Integer.parseInt(otp.toString());
    }

    @Override
    public String verifyEmail(int userOTP) throws EmailValidationException, SessionIdExpiredException {
        if (sessionId == null) {
            if (userOTP == getOtp().get(0).getOtp()) {
                jdbcTemplate.update("update users set account_status = ?", AccountStatus.VERIFIED.toString());
                return "Email verified successfully";
            }
            throw new EmailValidationException("Incorrect OTP");
        }
        throw new SessionIdExpiredException("You already logged in");
    }

    private List<OTPManager> getOtp() {
        return jdbcTemplate.query("Select * from otpManager where user_id = ? and email = ?",
                new BeanPropertyRowMapper<>(OTPManager.class), loggedUser.getUserId(), loggedUser.getEmail());
    }

    @Override
    public String sendOTP() throws OTPGenerateException {
        if (sessionId == null) {
            List<OTPManager> otpManager = getOtp();
            if (otpManager.isEmpty()) {
                int otp = generateOTP();
                SimpleMailMessage email = new SimpleMailMessage();
                email.setFrom("raspberrypi001025@gmail.com");
                email.setTo(loggedUser.getEmail());
                email.setSubject("OTP");
                email.setText("Enter the OTP to verify the account\n" + otp);
                javaMailSender.send(email);
                jdbcTemplate.update("Insert into OTPManager values (? , ? , ?)", loggedUser.getUserId(), loggedUser.getEmail(), otp);
            } else {
                SimpleMailMessage email = new SimpleMailMessage();
                email.setFrom("raspberrypi001025@gmail.com");
                email.setTo(loggedUser.getEmail());
                email.setSubject("OTP");
                email.setText("Enter the OTP to verify the account\n" + otpManager.get(0).getOtp());
                javaMailSender.send(email);
            }
            return "OTP sent Successfully";
        }
        throw new OTPGenerateException("Unable to send otp try again");
    }

    @Override
    public boolean verifyCard(long cardNumber) {
        return jdbcTemplate.query("select * from cards where cardNumber = ? and user_id = ?",
                new BeanPropertyRowMapper<>(Cards.class), cardNumber, loggedUser.getUserId()).isEmpty();
    }

    @Override
    public boolean verifyOrderId(String orderId) {
        return jdbcTemplate.query("select * from myOrderItems where orderId = ? ",
                new BeanPropertyRowMapper<>(MyOrderItems.class), orderId, loggedUser.getUserId()).isEmpty();
    }

    @Override
    public boolean verifyPaymentAvailability(String restaurantId, String paymentType) throws SessionIdExpiredException {
        checkSession();

        return !jdbcTemplate.query("Select * from payment where paymentType = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(Payment.class), paymentType, restaurantId).isEmpty();

    }

    @Override
    public void checkSession() throws SessionIdExpiredException {
        if (sessionId == null)
            throw new SessionIdExpiredException("login perform action");
    }


    /**
     * ******Home Interface******
     */

    @Override
    public Page<Restaurants> topRatedRestaurants(int pageNumber, int pageSize) throws SessionIdExpiredException {
        checkSession();

        return restaurantRepository.findAll(PageRequest.of(pageNumber, pageSize, Sort.by(Sort.Direction.ASC, "restaurantName")));

    }

    @Override
    public List<Categories> viewCategories(int pageNumber, int pageSize) throws SessionIdExpiredException {
        checkSession();

        int offset = pageSize * pageNumber;
        return jdbcTemplate.query("Select * from categories limit ? offset ?",
                new BeanPropertyRowMapper<>(Categories.class), pageSize, offset);

    }

    @Override
    public byte[] viewRestaurantPhoto(String restaurantId) throws SessionIdExpiredException, IOException {
        checkSession();

        Restaurants restaurant = restaurantRepository.findByRestaurantId(restaurantId).get(0);
        if (restaurant.getRestaurantPhoto() != null) {
            String photo = restaurant.getRestaurantPhoto();
            return Files.readAllBytes(Path.of(photo));
        }
        throw new NullPointerException("Photo not uploaded");
    }


    /**
     * ******Filter Interface******
     */


    @Override
    public List<String> viewSortOptions() throws SessionIdExpiredException {
        checkSession();

        List<String> sortOptions = new ArrayList<>();
        sortOptions.add("Top Rated");
        sortOptions.add("Cost Low To High");
        sortOptions.add("Cost High To Low");
        return sortOptions;

    }

    @Override
    public List<String> otherFilters() throws SessionIdExpiredException {
        checkSession();

        List<String> filters = new ArrayList<>();
        filters.add("Open Now");
        filters.add("Free Delivery");
        return filters;

    }

    @Override
    public List<String> showPaymentType() throws SessionIdExpiredException {
        checkSession();

        List<String> paymentType = new ArrayList<>();
        for (PaymentTypes paymentTypes : EnumSet.allOf(PaymentTypes.class))
            paymentType.add(paymentTypes.toString());
        return paymentType;

    }

    @Override
    public List<Restaurants> filterAll(String categoryName, String sortBy, int priceRange, boolean openNow, String paymentType, boolean freeDelivery, int pageSize, int pageNumber) throws SessionIdExpiredException {
        checkSession();

        int offset = pageSize * pageNumber;
        if (categoryName != null) {
            if (!freeDelivery)
                return withoutFreeDelivery(categoryName, sortBy, priceRange, openNow, paymentType, pageSize, offset);
            else
                return withFreeDelivery(categoryName, sortBy, priceRange, openNow, paymentType, pageSize, offset);
        }
        throw new NullPointerException("Select one of the category");

    }

    private List<Restaurants> withoutFreeDelivery(String categoryName, String sortBy, int priceRange, boolean openNow, String paymentType, int pageSize, int offset) {
        if (openNow)
            return withRestaurantOpensWithoutFreeDelivery(categoryName, sortBy, priceRange, paymentType, pageSize, offset);
        else
            return withRestaurantClosesWithoutFreeDelivery(categoryName, sortBy, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> withRestaurantOpensWithoutFreeDelivery(String categoryName, String sortBy, int priceRange, String paymentType, int pageSize, int offset) {
        if (sortBy.equalsIgnoreCase("Cost High To Low"))
            return highToLowWithOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Cost Low To High"))
            return lowToHighWithOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Top Rated"))
            return topRatedWithOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);
        else
            return normalWithOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

    }

    private List<Restaurants> normalWithOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME()) " +
                        "limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> topRatedWithOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?)" +
                        " and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME()) " +
                        "order by ratings DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> lowToHighWithOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?)" +
                        " and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME()) " +
                        "order by itemPrice ASC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> highToLowWithOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? )" +
                        " and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME()) " +
                        "order by itemPrice DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> withRestaurantClosesWithoutFreeDelivery(String categoryName, String sortBy, int priceRange, String paymentType, int pageSize, int offset) {
        if (sortBy.equalsIgnoreCase("Cost High To Low"))
            return highToLowWithoutOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Cost Low To High"))
            return lowToHighWithoutOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Top Rated"))
            return topRatedWithoutOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else
            return normalWithoutOpenWithoutFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

    }

    private List<Restaurants> normalWithoutOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?)  " +
                        "limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> topRatedWithoutOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "order by ratings DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> lowToHighWithoutOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "order by itemPrice ASC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> highToLowWithoutOpenWithoutFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "order by itemPrice DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> withFreeDelivery(String categoryName, String sortBy, int priceRange, boolean openNow, String paymentType, int pageSize, int offset) {
        if (openNow)
            return withRestaurantOpenWithFreeDelivery(categoryName, sortBy, priceRange, paymentType, pageSize, offset);
        else
            return withRestaurantCloseWithFreeDelivery(categoryName, sortBy, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> withRestaurantCloseWithFreeDelivery(String categoryName, String sortBy, int priceRange, String paymentType, int pageSize, int offset) {
        if (sortBy.equalsIgnoreCase("Cost High To Low"))
            return highToLowWithoutOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Cost Low To High"))
            return lowToHighWithoutOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Top Rated"))
            return topRatedWithoutOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else
            return normalWithoutOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

    }

    private List<Restaurants> normalWithoutOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from categories where freeDelivery = 0) " +
                        "limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);

    }

    private List<Restaurants> topRatedWithoutOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select * from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from categories where freeDelivery = 0) " +
                        "order by ratings DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> lowToHighWithoutOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from categories where freeDelivery = 0) " +
                        "order by itemPrice ASC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> highToLowWithoutOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from categories where freeDelivery = 0) " +
                        "order by itemPrice DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> withRestaurantOpenWithFreeDelivery(String categoryName, String sortBy, int priceRange, String paymentType, int pageSize, int offset) {

        if (sortBy.equalsIgnoreCase("Cost High To Low"))
            return highToLowWithOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Cost Low To High"))
            return lowToHighWithOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else if (sortBy.equalsIgnoreCase("Top Rated"))
            return topRatedWithOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

        else
            return normalWithOpenWithFreeDeliveryResult(categoryName, priceRange, paymentType, pageSize, offset);

    }

    private List<Restaurants> normalWithOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME()) " +
                        "and restaurant_id in( select restaurant_id from categories where freeDelivery = 0) " +
                        "limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> topRatedWithOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME()) " +
                        "and restaurant_id in( select restaurant_id from categories where freeDelivery = 0) " +
                        "order by ratings DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> lowToHighWithOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME())" +
                        "and restaurant_id in( select restaurant_id from categories where freeDelivery = 0) " +
                        "order by itemPrice ASC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }

    private List<Restaurants> highToLowWithOpenWithFreeDeliveryResult(String categoryName, int priceRange, String paymentType, int pageSize, int offset) {
        return jdbcTemplate.query("Select * from Restaurants where restaurant_id in(select restaurant_id from categories where categoryName = ?) " +
                        "and restaurant_id in( select restaurant_id from menu where itemPrice <= ? ) " +
                        "and restaurant_id in(select restaurant_id from payment where paymentType = ?) " +
                        "and restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME()) " +
                        "and restaurant_id in( select restaurant_id from categories where freeDelivery = 0) " +
                        "order by itemPrice DESC limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), categoryName, priceRange, paymentType, pageSize, offset);
    }


    /**
     * ******Categories Interface******
     */


    @Override
    public List<Categories> showAllCategoriesOfRestaurant(String restaurantId, int pageSize, int pageNumber) throws SessionIdExpiredException {
        checkSession();

        int offset = pageSize * pageNumber;
        return jdbcTemplate.query("Select * from categories where restaurant_id = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(Categories.class), restaurantId, pageSize, offset);

    }


    /**
     * ******Menu Interface******
     */

    @Override
    public List<Menu> viewMenuOfRestaurant(String restaurantId, String categoryName, int pageSize, int pageNumber) throws SessionIdExpiredException {
        checkSession();

        int offset = pageSize * pageNumber;
        return jdbcTemplate.query("Select * from menu where restaurant_id = ? and categoryName = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(Menu.class), restaurantId, categoryName, pageSize, offset);

    }

    @Override
    public List<Menu> viewMenuOfCategory(String categoryName, int pageSize, int pageNumber) throws SessionIdExpiredException {
        checkSession();

        int offset = pageSize * pageNumber;
        return jdbcTemplate.query("Select * from menu where categoryName = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(Menu.class), categoryName, pageSize, offset);

    }

    @Override
    public Menu getDishDetails(String restaurantId, String categoryName, String itemName) {
        return jdbcTemplate.query("Select * from menu where restaurant_id = ? and categoryName = ? and itemName = ?",
                new BeanPropertyRowMapper<>(Menu.class), restaurantId, categoryName, itemName).get(0);
    }


    /**
     * ******Cards Interface******
     */

    @Override
    public String addCards(long cardNumber) throws SessionIdExpiredException {
        checkSession();

        if (verifyCard(cardNumber)) {
            jdbcTemplate.update("Insert into cards values(?,?)", loggedUser.getUserId(), cardNumber);
            return "card added successfully";
        }
        throw new NullPointerException("Card already added");

    }

    @Override
    public String removeCard(long cardNumber) throws SessionIdExpiredException {
        checkSession();

        if (!verifyCard(cardNumber)) {
            jdbcTemplate.update("delete from cards where cardNumber = ? and user_id = ?",
                    cardNumber, loggedUser.getUserId());
            return "card Removed Successfully";
        }
        throw new NullPointerException("Card not found");

    }

    @Override
    public List<Cards> viewAllCards() throws SessionIdExpiredException {
        checkSession();

        return jdbcTemplate.query("Select * from cards where user_id = ?",
                new BeanPropertyRowMapper<>(Cards.class), loggedUser.getUserId());

    }


    /**
     * ******Order Interface******
     */

    @Override
    public List<MyOrders> addOrders(String restaurantId, Map<String, Map<String, Integer>> orders, String paymentType) throws SessionIdExpiredException {
        checkSession();

        int totalBill = 0;
        String orderId = generateId();
        if (!verifyOrderId(orderId))
            addOrders(restaurantId, orders, paymentType);
        for (String categoryName : orders.keySet()) {
            //extracting item name with number of items
            Map<String, Integer> items = orders.get(categoryName);
            //
            for (String itemName : items.keySet()) {
                Menu itemDetails = getDishDetails(restaurantId, categoryName, itemName);
                totalBill += items.get(itemName) * itemDetails.getItemPrice();
                jdbcTemplate.update("Insert into myOrderItems values(?,?,?,?)", orderId, itemName, categoryName, items.get(itemName));
            }
        }
        jdbcTemplate.update("Insert into myOrders values(?,?,?,?,?,?,?)", orderId, loggedUser.getUserId(), restaurantId,
                LocalDateTime.now(), totalBill, paymentType, OrderStatus.PAYMENTPENDING.toString());
        return jdbcTemplate.query("select * from myOrders where orderId = ?",
                new BeanPropertyRowMapper<>(MyOrders.class), orderId);
    }

    @Override
    public String makePayment(String restaurantId, String orderId, String paymentType, Long cardNumber) throws SessionIdExpiredException, InvalidCardNumberException {
        checkSession();

        if (verifyPaymentAvailability(restaurantId, paymentType)) {
            updatePaymentType(paymentType, orderId);
            if (cardNumber != null) {
                if (Long.toString(cardNumber).length() == 12) {
                    return bookOrderToHotel(restaurantId, orderId);
                }
                throw new InvalidCardNumberException("Invalid card number");
            } else {
                return bookOrderToHotel(restaurantId, orderId);
            }
        }
        return "Select other payment type";
    }

    private void updatePaymentType(String paymentType, String orderId) {
        jdbcTemplate.update("update myOrders set paymentType = ? where orderId = ?", paymentType);
    }

    private String bookOrderToHotel(String restaurantId, String orderId) {

        int totalBill = jdbcTemplate.query("select 8 from myOrders where orderId = ?",
                new BeanPropertyRowMapper<>(MyOrders.class), orderId).get(0).getTotalBill();
        jdbcTemplate.update("update myOrders set orderStatus = ? where orderId = ?", OrderStatus.CONFIRMED.toString(),
                orderId);
        jdbcTemplate.update("insert into values(?,?,?)", restaurantId, orderId, totalBill);
        return "your order confirmed.Thank you";

    }


    /**
     * ******Rating Interface******
     */

    @Override
    public void rating(String orderId) throws SessionIdExpiredException {
        checkSession();
        MyOrders myOrder = jdbcTemplate.query("Select * from myOrders where orderId = ?",
                new BeanPropertyRowMapper<>(MyOrders.class), orderId).get(0);
        int newRatings = restaurantRepository.findByRestaurantId(myOrder.getRestaurantId()).get(0).getRatings() + 1;
        jdbcTemplate.update("update restaurants set ratings = ? where restaurant_id = ?",
                newRatings, myOrder.getRestaurantId());
    }

    @Override
    public String addToFavourite(String restaurantName) throws SessionIdExpiredException {
        checkSession();
        jdbcTemplate.update("insert into favourites(?,?)", loggedUser.getUserId(), restaurantName);
        return "restaurant added to your favourite list";
    }

    @Override
    public String deleteFavourite(String restaurantName) throws SessionIdExpiredException {
        checkSession();
        List<Favourite> favourite = jdbcTemplate.query("select * from favourites where restaurantName = ?",
                new BeanPropertyRowMapper<>(Favourite.class), restaurantName);
        if (!favourite.isEmpty()) {
            jdbcTemplate.update("delete from favourites where restaurantName = ?", restaurantName);
            return "removed successfully";
        }
        throw new NullPointerException("restaurant not found");

    }

    @Override
    public List<Favourite> viewFavorites() throws SessionIdExpiredException {
        checkSession();
        return jdbcTemplate.query("select * from favourite", new BeanPropertyRowMapper<>(Favourite.class));
    }


    /**
     * ******Search Interface******
     */

    @Override
    public List<?> search(String field) throws SessionIdExpiredException {
        checkSession();
        List<Restaurants> restaurants = restaurantRepository.findByRestaurantName(field);
        List<Categories> categories = jdbcTemplate.query("select * from categories where categoryName = ?",
                new BeanPropertyRowMapper<>(Categories.class), field);
        List<Menu> menu = jdbcTemplate.query("select * from menu where itemName = ?",
                new BeanPropertyRowMapper<>(Menu.class), field);
        if (!restaurants.isEmpty())
            return restaurants;
        if (!categories.isEmpty())
            return categories;
        if (!menu.isEmpty())
            return menu;
        throw new NullPointerException("no data found");
    }
}
