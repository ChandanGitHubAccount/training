package zomatomodified.zomato.service.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import zomatomodified.zomato.coustomexcptions.*;
import zomatomodified.zomato.entity.Categories;
import zomatomodified.zomato.entity.Users;
import zomatomodified.zomato.model.*;
import zomatomodified.zomato.repository.CategoryRepository;
import zomatomodified.zomato.repository.UserRepository;
import zomatomodified.zomato.security.userdetails.JWTUserDetailsService;
import zomatomodified.zomato.security.utility.JWTUtility;
import zomatomodified.zomato.service.*;
import zomatomodified.zomato.service.system.LoggedUser;
import zomatomodified.zomato.service.system.SystemInterface;
import zomatomodified.zomato.service.system.TokenInterface;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class UserService implements LoginInterface, HomeInterface, FilterInterface, CategoriesInterface, DishInterface, CardInterface, OrderInterface, RatingInterface, SearchInterface, RoleInterface {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private SystemInterface systemInterface;

    @Autowired
    private TokenInterface tokenInterface;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private JWTUserDetailsService jwtUserDetailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private LoggedUser loggedUsers;

    private Users loggedUser;

    private static final String userProfileFilePath = "C:\\Users\\Chandan H U\\Desktop\\userProfilePhoto";


    /**
     * ******Login Interface******
     */

    @Override
    public String signIn(String email, String password) throws LoginFailedException {
        try {
            List<Users> user = userRepository.findByEmail(email);
            if (user.get(0).getAccountStatus().equalsIgnoreCase(AccountStatus.NOTVERIFIED.toString()))
                return "verify the email before login";
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            final UserDetails userDetail = jwtUserDetailsService.loadUserByUsername(email);
            loggedUsers.setLoggedUser(user.get(0));
            this.loggedUser = loggedUsers.getUsers();
            return "Login Successful with token : " + jwtUtility.generateToken(userDetail);
        } catch (BadCredentialsException exception) {
            throw new LoginFailedException("Invalid credentials");
        }
    }

    @Override
    public String signUp(Users user, MultipartFile profilePhoto) throws SignupException {
        try {
            String userId = systemInterface.generateId();
            if (userRepository.findById(userId).isPresent())
                signUp(user, profilePhoto);

            user.setUserId(userId);
            user.setCreatedDate(LocalDate.now());
            user.setAccountStatus(AccountStatus.NOTVERIFIED.toString());
            if (user.getGstNumber().length() == 15)
                user.setRole(Role.ADMIN.toString());
            else
                user.setRole(Role.CUSTOMER.toString());
            if (profilePhoto.getOriginalFilename() != null) {
                user.setProfilePhoto(userProfileFilePath + File.separator + profilePhoto.getOriginalFilename());
                profilePhoto.transferTo(Path.of(userProfileFilePath + File.separator + profilePhoto.getOriginalFilename()));
            } else user.setProfilePhoto(null);
            if (systemInterface.checkForDuplicateRegistration(user.getEmail(), user.getPhoneNumber())) {
                userRepository.save(user);
                return "Account successfully created";
            }
            return "Email or Phone number already registered";
        } catch (Exception exception) {
            throw new SignupException("Failed to register.Please provide valid details");
        }
    }

    @Override
    public String forgotPassword(String email) throws UsernameNotFoundException {
        if (!systemInterface.checkAvailabilityOfEmail(email)) {
            String token = tokenInterface.generate();
            if (!tokenInterface.verifyToken(token))
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

    @Override
    public String signOut() throws SignOutException {
        try {
            this.loggedUser = null;
            return "sign out successful";
        } catch (Exception exception) {
            throw new SignOutException("sign out failed.try again after sometime.");
        }
    }

    @Override
    public String resetPassword(String token, String newPassword, String confirmPassword) throws SessionIdExpiredException, TokenExpiredException {
        List<Tokens> tokens = tokenInterface.getTokenDetail(token);
        if (!tokens.isEmpty()) {
            if (newPassword.equals(confirmPassword)) {
                if (tokens.get(0).getExpireAt().compareTo(LocalDateTime.now()) >= 0) {
                    jdbcTemplate.update("update users set password = ? where username = ? ", newPassword, tokens.get(0).getUserId());
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
    public String changePassword(String newPassword, String confirmPassword) {
        try {
            if (newPassword.equals(confirmPassword)) {
                jdbcTemplate.update("update users set password = ? where user_id = ?", passwordEncoder.encode(newPassword), loggedUser.getUserId());
                return "Password updated successfully";
            }
            throw new Exception("password miss matched");
        } catch (Exception exception) {
            throw new NullPointerException("login to perform action");
        }
    }

    @Override
    public String changeProfilePhoto(MultipartFile profilePhoto) throws IOException, UpdateFailedException {
        if (profilePhoto.getOriginalFilename() != null) {
            deleteOldProfilePhoto();
            String setProfilePhoto = userProfileFilePath + File.separator + profilePhoto.getOriginalFilename();
            jdbcTemplate.update("update users set profile_photo = ? where user_id = ?", setProfilePhoto, loggedUser.getUserId());
            profilePhoto.transferTo(Path.of(setProfilePhoto));
            return "Profile photo uploaded successfully";
        }
        throw new UpdateFailedException("Profile photo uploading failed");
    }

    @Override
    public byte[] viewProfilePhoto() throws IOException {
        Users user = userRepository.findByUserId(loggedUser.getUserId()).get(0);
        if (user.getProfilePhoto() != null) {
            String photo = user.getProfilePhoto();
            return Files.readAllBytes(Path.of(photo));
        }
        throw new NullPointerException("Photo not uploaded");
    }

    @Override
    public String deleteOldProfilePhoto() throws IOException {
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
     * ******Home Interface******
     */

    @Override
    public List<Restaurants> topRatedRestaurants(int pageNumber, int pageSize) {
        int offset = pageSize * (pageNumber - 1);
        return jdbcTemplate.query("select * from restaurants order by ratings DESC limit ? offset ? ",
                new BeanPropertyRowMapper<>(Restaurants.class), pageSize, offset);
    }

    @Override
    public List<Categories> viewCategories(int pageNumber, int pageSize) {

        int offset = pageSize * (pageNumber - 1);
        return jdbcTemplate.query("Select * from categories limit ? offset ?",
                new BeanPropertyRowMapper<>(Categories.class), pageSize, offset);

    }

    @Override
    public byte[] viewRestaurantPhoto(String restaurantId) throws IOException {

        Restaurants restaurant = jdbcTemplate.query("select * from restaurants where restaurant_id = ? ",
                new BeanPropertyRowMapper<>(Restaurants.class), restaurantId).get(0);
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
    public List<String> viewSortOptions() {

        List<String> sortOptions = new ArrayList<>();
        sortOptions.add("Top Rated");
        sortOptions.add("Cost Low To High");
        sortOptions.add("Cost High To Low");
        return sortOptions;

    }

    @Override
    public List<String> otherFilters() {

        List<String> filters = new ArrayList<>();
        filters.add("Open Now");
        filters.add("Free Delivery");
        filters.add("CreditCard");
        return filters;

    }

    @Override
    public List<String> showPaymentType() {
        List<String> paymentTypes = new ArrayList<>();
        for (PaymentTypes types : PaymentTypes.values())
            paymentTypes.add(types.toString());
        return paymentTypes;
    }

    @Override
    public List<Restaurants> filterAll(FilterModel filterModel, int pageSize, int pageNumber) {
        int offset = pageSize * (pageNumber - 1);

        String query = "Select * from Restaurants where ";
        String categoryFilter = "restaurant_id in(select restaurant_id from restaurantCategory where category_id = ";
        String freeDeliveryFilter = "restaurant_id in( select restaurant_id from dish where itemPrice = 0 )";
        String open = "restaurant_id in(select restaurant_id from restaurants where close_at >= CURRENT_TIME())";
        String payment = "restaurant_id in(select restaurant_id from restaurantPayments where paymentType = 'CREDITCARD'";
        String lowToHigh = " restaurant_id in(select restaurant_id from dish where itemPrice <= ? order by itemPrice ASC)";
        String highToLow = " restaurant_id in(select restaurant_id from dish where itemPrice <= ? order by itemPrice DESC)";
        String topRated = " order by ratings";
        String paging = " limit ? offset ?";
        String separator = " and ";

        if (filterModel.getCategoryId() != null)
            query += categoryFilter + "'" + filterModel.getCategoryId() + "')" + separator;

        if (filterModel.isOpenNow())
            query += open + separator;
        if (filterModel.isCreditCard())
            query += payment + separator;
        if (filterModel.isFreeDelivery())
            query += freeDeliveryFilter + separator;

        if (query.endsWith(" and "))
            query = query.substring(0, (query.length() - 5));
//change price filter as all done
        if (filterModel.getSortBy() != null) {
            String substring = query.substring(0, (query.length() - 7));
            if (filterModel.getPriceRange() > 0) {
                if (filterModel.getSortBy().equalsIgnoreCase("Cost High To Low"))
                    return jdbcTemplate.query(query + highToLow + paging, new BeanPropertyRowMapper<>(Restaurants.class),
                            filterModel.getPriceRange(), pageSize, offset);
                else if (filterModel.getSortBy().equalsIgnoreCase("Cost Low To High"))
                    return jdbcTemplate.query(query + lowToHigh + paging, new BeanPropertyRowMapper<>(Restaurants.class),
                            filterModel.getPriceRange(), pageSize, offset);
                else if (filterModel.getSortBy().equalsIgnoreCase("Top Rated")) {
                    if (query.endsWith(" where "))
                        query = substring;
                    return jdbcTemplate.query(query + topRated + paging, new BeanPropertyRowMapper<>(Restaurants.class),
                            pageSize, offset);
                }
            } else {
                if (filterModel.getSortBy().equalsIgnoreCase("Cost High To Low"))
                    return jdbcTemplate.query(query + highToLow + paging, new BeanPropertyRowMapper<>(Restaurants.class),
                            "itemPrice", pageSize, offset);
                else if (filterModel.getSortBy().equalsIgnoreCase("Cost Low To High"))
                    return jdbcTemplate.query(query + lowToHigh + paging, new BeanPropertyRowMapper<>(Restaurants.class),
                            "itemPrice", pageSize, offset);
                else if (filterModel.getSortBy().equalsIgnoreCase("Top Rated")) {
                    if (query.endsWith(" where "))
                        query = substring;
                    return jdbcTemplate.query(query + topRated + paging, new BeanPropertyRowMapper<>(Restaurants.class),
                            pageSize, offset);
                }
            }
        }

        if (query.length() > 40)
            return jdbcTemplate.query(query + lowToHigh + paging, new BeanPropertyRowMapper<>(Restaurants.class),
                    filterModel.getPriceRange(), pageSize, offset);
        else return null;
    }

    /**
     * ******Categories Interface******
     */


    @Override
    public List<Categories> showAllCategoriesOfRestaurant(String restaurantId, int pageSize, int pageNumber) {

        int offset = pageSize * (pageNumber - 1);
        List<RestaurantCategory> restaurantCategories = jdbcTemplate.query("Select * from restaurantCategory where restaurant_id = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(RestaurantCategory.class), restaurantId, pageSize, offset);
        List<Categories> categories = new ArrayList<>();
        for (RestaurantCategory restaurantCategory : restaurantCategories)
            categories.add(categoryRepository.findByCategoryId(restaurantCategory.getCategoryId()).get(0));

        return categories;
    }


    /**
     * ******Dish Interface******
     */

    @Override
    public List<Dish> viewDishOfRestaurant(String restaurantId, int pageSize, int pageNumber) {

        int offset = pageSize * (pageNumber - 1);
        return jdbcTemplate.query("Select * from Dish where restaurant_id = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(Dish.class), restaurantId, pageSize, offset);

    }

    @Override
    public List<Dish> viewDishOfCategory(String categoryId, int pageSize, int pageNumber) {

        int offset = pageSize * (pageNumber - 1);

        return jdbcTemplate.query("Select * from Dish where category_id = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(Dish.class), categoryId, pageSize, offset);

    }

    @Override
    public Dish getDishDetails(String itemId) {
        List<Dish> dishes = jdbcTemplate.query("Select * from Dish where itemId = ? ",
                new BeanPropertyRowMapper<>(Dish.class), itemId);
        return dishes.isEmpty() ? null : dishes.get(0);
    }

    /**
     * ******Cards Interface******
     */

    @Override
    public String addCards(long cardNumber) throws InvalidCardNumberException {

        if (String.valueOf(cardNumber).length() != 12)
            throw new InvalidCardNumberException("Invalid card number");
        if (systemInterface.verifyCard(cardNumber, loggedUser.getUserId())) {
            jdbcTemplate.update("Insert into cards values(?,?)", loggedUser.getUserId(), cardNumber);
            return "card added successfully";
        }
        throw new NullPointerException("Card already added");

    }

    @Override
    public String removeCard(long cardNumber) throws InvalidCardNumberException {
        if (String.valueOf(cardNumber).length() != 12)
            throw new InvalidCardNumberException("Invalid card number");
        if (!systemInterface.verifyCard(cardNumber, loggedUser.getUserId())) {
            jdbcTemplate.update("delete from cards where cardNumber = ? and user_id = ?",
                    cardNumber, loggedUser.getUserId());
            return "card Removed Successfully";
        }
        throw new NullPointerException("Card not found");

    }

    @Override
    public List<Cards> viewAllCards() {

        return jdbcTemplate.query("Select * from cards where user_id = ?",
                new BeanPropertyRowMapper<>(Cards.class), loggedUser.getUserId());
    }

    /**
     * ******Order Interface******
     */

    @Override
    public List<MyOrders> addOrders(String restaurantId, Map<String, Map<String, Integer>> orders, String paymentType) {

        int totalBill = 0;
        String orderId = systemInterface.generateId();
        if (!systemInterface.verifyOrderId(orderId))
            addOrders(restaurantId, orders, paymentType);
        jdbcTemplate.update("Insert into myOrders values(?,?,?,?,?,?,?)", orderId, loggedUser.getUserId(), restaurantId,
                LocalDateTime.now(), 0, paymentType, OrderStatus.PAYMENTPENDING.toString());
        for (String categoryId : orders.keySet()) {
            //extracting item name with number of items
            Map<String, Integer> items = orders.get(categoryId);
            //
            for (String itemId : items.keySet()) {
                Dish itemDetails = getDishDetails(itemId);
                totalBill += items.get(itemId) * itemDetails.getItemPrice();
                jdbcTemplate.update("Insert into myOrderItems values(?,?,?,?)", orderId, itemId, categoryId, items.get(itemId));
            }
        }
        jdbcTemplate.update("update myOrders set totalBill = ? where orderId = ?", totalBill, orderId);
        return jdbcTemplate.query("select * from myOrders where orderId = ?",
                new BeanPropertyRowMapper<>(MyOrders.class), orderId);
    }

    @Override
    public String makePayment(String restaurantId, String orderId, String paymentType, Long cardNumber) throws InvalidCardNumberException {

        if (systemInterface.verifyPaymentAvailability(restaurantId, paymentType)) {
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
        jdbcTemplate.update("update myOrders set paymentMethod = ? where orderId = ?", paymentType, orderId);
    }

    private String bookOrderToHotel(String restaurantId, String orderId) {

        int totalBill = jdbcTemplate.query("select * from myOrders where orderId = ?",
                new BeanPropertyRowMapper<>(MyOrders.class), orderId).get(0).getTotalBill();
        jdbcTemplate.update("update myOrders set orderStatus = ? where orderId = ?", OrderStatus.CONFIRMED.toString(),
                orderId);
        jdbcTemplate.update("insert into restaurantOrders values(?,?,?,?)", restaurantId, orderId, totalBill, LocalDate.now());
        return "your order confirmed.Thank you";

    }


    /**
     * ******Rating Interface******
     */

    @Override
    public void rating(String orderId) {
        List<MyOrders> myOrder = jdbcTemplate.query("Select * from myOrders where orderId = ?",
                new BeanPropertyRowMapper<>(MyOrders.class), orderId);
        if (myOrder.isEmpty())
            return;

        int ratings = jdbcTemplate.query("select * from restaurants where restaurant_id = ?",
                new BeanPropertyRowMapper<>(Restaurants.class), myOrder.get(0).getRestaurantId()).get(0).getRatings();

        if (jdbcTemplate.query("select * from ratingDetails where orderId = ?",
                new BeanPropertyRowMapper<>(RatingDetails.class), orderId).isEmpty())
            ratings += 1;
        else
            ratings -= 1;
        jdbcTemplate.update("update restaurants set ratings = ? where restaurant_id = ?",
                ratings, myOrder.get(0).getRestaurantId());

    }

    @Override
    public String addToFavourite(String restaurantId) {
        List<Favourites> favourites = jdbcTemplate.query("select * from favourites where restaurant_id = ?",
                new BeanPropertyRowMapper<>(Favourites.class), restaurantId);
        if (favourites.isEmpty()) {
            jdbcTemplate.update("insert into favourites values(?,?)", loggedUser.getUserId(), restaurantId);
            return "restaurant added to your favourite list";
        }
        return deleteFavourite(restaurantId);
    }

    @Override
    public String deleteFavourite(String restaurantId) {
        jdbcTemplate.update("delete from favourites where restaurant_id = ?", restaurantId);
        return "removed from favourites";
    }

    @Override
    public List<Restaurants> viewFavorites() {
        List<Favourites> favourites = jdbcTemplate.query("select * from favourites", new BeanPropertyRowMapper<>(Favourites.class));
        List<Restaurants> restaurants = new ArrayList<>();
        for (Favourites restaurantId : favourites)
            restaurants.add(jdbcTemplate.query("select * from restaurants where restaurant_id = ?",
                    new BeanPropertyRowMapper<>(Restaurants.class), restaurantId.getRestaurantId()).get(0));
        return restaurants;
    }

    /**
     * ******Search Interface******
     */

    @Override
    public List<?> search(String field, int pageSize, int pageNumber) {
        int offset = pageSize * (pageNumber - 1);
        List<Restaurants> restaurants = jdbcTemplate.query("select * from restaurants where restaurant_name = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), field, pageSize, offset);
        List<Categories> categories = jdbcTemplate.query("select * from categories where category_name = ? limit ? offset ?",
                new BeanPropertyRowMapper<>(Categories.class), field, pageSize, offset);
        List<Restaurants> restaurants1 = new ArrayList<>();
        if (!categories.isEmpty())
            restaurants1 = jdbcTemplate.query("select * from restaurants where restaurant_id in" +
                            "(select restaurant_id from restaurantCategory where category_id = ?) limit ? offset ?",
                    new BeanPropertyRowMapper<>(Restaurants.class), categories.get(0).getCategoryId(), pageSize, offset);

        List<Restaurants> restaurants2 = jdbcTemplate.query("select * from restaurants where restaurant_id in" +
                        "(select restaurant_id from dish where itemName = ?) limit ? offset ?",
                new BeanPropertyRowMapper<>(Restaurants.class), field, pageSize, offset);
        if (!restaurants.isEmpty())
            return restaurants;
        if (!restaurants1.isEmpty())
            return restaurants1;
        if (!restaurants2.isEmpty())
            return restaurants2;
        throw new NullPointerException("no data found");
    }


    /**
     * ******Role Interface******
     */

    @Override
    public String changeRole(String gstNumber) throws InvalidCardNumberException {
        if (systemInterface.verifyGstNumber(gstNumber)) {
            jdbcTemplate.update("update users set role = ? where user_id = ?", Role.ADMIN.toString(), loggedUser.getUserId());
            return "role changed successfully.please logout and login to perform admin operation";
        }
        throw new InvalidCardNumberException("enter valid gst number");
    }

    @Override
    public String editUser(Users users) {
        jdbcTemplate.update("update users set username = ? , gender = ? , age = ? ", users.getUsername(), users.getGender(), users.getAge());
        List<Users> user = userRepository.findByEmail(users.getEmail());
        if (user.isEmpty()) {
            jdbcTemplate.update("update users set email = ? , account_status = ?", users.getEmail(), AccountStatus.NOTVERIFIED);
            return "updated successfully please verify email";
        }
        return "updated successfully";
    }

}

