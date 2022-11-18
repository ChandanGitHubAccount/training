package zomato.service.restaurant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.InvalidTimeException;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.coustomexcptions.UpdateFailedException;
import zomato.entity.Restaurants;
import zomato.model.Categories;
import zomato.model.Menu;
import zomato.model.Payment;
import zomato.model.RestaurantOrders;
import zomato.repositatory.RestaurantRepository;
import zomato.service.Days;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Random;

@Service
public class RestaurantOwnerService implements RestaurantInterface, CategoryInterface, MenuInterface, PaymentInterface, RestaurantOrdersInterface {

    private static final String restaurantFilePath = "C:\\Users\\Chandan H U\\Desktop\\restaurantPhoto";

    private static final String dishFilePath = "C:\\Users\\Chandan H U\\Desktop\\dishPhoto";

    @Autowired
    private RestaurantRepository restaurantRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private Restaurants loggedOwner;

    private String sessionId;


    /**
     * Restaurant functions
     */

    private String generateSession() {
        return Integer.toString(new Random().nextInt(1000, 10000));
    }

    private void checkSession() throws SessionIdExpiredException {
        if (sessionId == null)
            throw new SessionIdExpiredException("Login to perform the action");
    }

    @Override
    public String Login(String restaurantId) throws SessionIdExpiredException {
        if (sessionId == null) {
            Optional<Restaurants> restaurant = restaurantRepository.findById(restaurantId);
            if (restaurant.isEmpty())
                return "Invalid restaurantId";
            this.loggedOwner = restaurant.get();
            this.sessionId = generateSession();
            return "Login Successful with Session Id : " + sessionId;
        }
        throw new SessionIdExpiredException("you are already logged in. please logout for new sign in");
    }

    @Override
    public String register(String restaurantId, String restaurantName, String restaurantAddress, LocalTime openAt,
                           LocalTime closeAt, String closeOn, MultipartFile photo) throws IOException, SessionIdExpiredException {
        if (sessionId == null) {
            if (restaurantRepository.findById(restaurantId).isEmpty()) {
                Restaurants restaurant = new Restaurants();
                if (photo.getOriginalFilename() != null) {
                    String restaurantPhoto = restaurantFilePath + File.separator + photo.getOriginalFilename();
                    photo.transferTo(Path.of(restaurantPhoto));
                    restaurant.setRestaurantPhoto(restaurantPhoto);
                }
                restaurant.setRestaurantId(restaurantId);
                restaurant.setRestaurantAddress(restaurantAddress);
                restaurant.setCloseAt(closeAt);
                restaurant.setOpenAt(openAt);
                restaurant.setCloseOn(closeOn);
                restaurant.setRestaurantName(restaurantName);
                restaurant.setRatings(0);
                restaurantRepository.save(restaurant);
                return "Restaurant registration successful";
            } else return "restaurant already registered";
        }
        throw new SessionIdExpiredException("Please logout before signup");
    }

    @Override
    public Restaurants viewRestaurantDetails() throws SessionIdExpiredException {
        checkSession();
        return restaurantRepository.findByRestaurantId(loggedOwner.getRestaurantId()).get(0);
    }

    @Override
    public byte[] viewRestaurantPhoto() throws SessionIdExpiredException, IOException {
        checkSession();
        Restaurants restaurant = restaurantRepository.findByRestaurantId(loggedOwner.getRestaurantId()).get(0);
        String path = restaurant.getRestaurantPhoto();
        if (path != null)
            return Files.readAllBytes(Path.of(path));
        throw new NullPointerException("Restaurant image not uploaded");
    }

    @Override
    public String changeRestaurantPhoto(MultipartFile photo) throws IOException, SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (photo.getOriginalFilename() != null) {
            deleteRestaurantPhoto();
            String setRestaurantPhoto = restaurantFilePath + File.separator + photo.getOriginalFilename();
            jdbcTemplate.update("update restaurants set restaurant_photo = ? where restaurant_id = ?",
                    setRestaurantPhoto, loggedOwner.getRestaurantId());
            photo.transferTo(Path.of(setRestaurantPhoto));
            return "Photo uploaded successfully";
        }
        throw new UpdateFailedException("Select proper picture");

    }

    @Override
    public String changeOpenTime(int openHour, int openMinutes) throws SessionIdExpiredException, InvalidTimeException {
        checkSession();
        if (openHour < 23 && openHour > 0 && openMinutes > 0 && openMinutes < 59)
            jdbcTemplate.update("update restaurants set restaurant_photo = ? where restaurant_id = ?",
                    LocalTime.of(openHour, openMinutes, 0), loggedOwner.getRestaurantId());
        throw new InvalidTimeException("Enter hour in the range 0 to 23 and minute in the range 0 to 59");

    }

    @Override
    public String changeCloseTime(int closeHour, int closeMinutes) throws SessionIdExpiredException, InvalidTimeException {
        checkSession();
        if (closeHour < 23 && closeHour > 0 && closeMinutes > 0 && closeMinutes < 59)
            jdbcTemplate.update("update restaurants set restaurant_photo = ? where restaurant_id = ?",
                    LocalTime.of(closeHour, closeMinutes, 0), loggedOwner.getRestaurantId());
        throw new InvalidTimeException("Enter hour in the range 0 to 23 and minute in the range 0 to 59");

    }

    @SuppressWarnings("SuspiciousMethodCalls")
    @Override
    public String changeCloseDay(String day) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (EnumSet.allOf(Days.class).contains(day.toUpperCase())) {
            jdbcTemplate.update("update restaurants set close_on = ? where restaurant_id = ?",
                    day.toUpperCase(), loggedOwner.getRestaurantId());
            return "close day updated successfully";
        }
        throw new UpdateFailedException("enter valid day or none to if your restaurant open on every day");

    }

    @Override
    public String changeRestaurantAddress(String restaurantAddress) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (restaurantAddress != null)
            jdbcTemplate.update("update restaurants set restaurant_address = ? where restaurant_id = ?",
                    restaurantAddress, loggedOwner.getRestaurantId());
        throw new UpdateFailedException("restaurant address is empty");

    }

    @Override
    public String changeRestaurantName(String restaurantName) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (restaurantName != null)
            jdbcTemplate.update("update restaurants set restaurant_name = ? where restaurant_id = ?",
                    restaurantName, loggedOwner.getRestaurantId());
        throw new UpdateFailedException("restaurant name is empty");

    }

    @Override
    public String deleteRestaurantPhoto() throws SessionIdExpiredException, IOException {
        checkSession();
        List<Restaurants> restaurant = jdbcTemplate.query("Select * from restaurants where restaurant_id = ?",
                new BeanPropertyRowMapper<>(Restaurants.class), loggedOwner.getRestaurantId());
        String path = restaurant.get(0).getRestaurantPhoto();
        if (path != null) {
            Files.deleteIfExists(Path.of(path));
            jdbcTemplate.update("Update restaurants set restaurant_photo = ? where restaurant_id = ?",
                    null, loggedOwner.getRestaurantId());
            return "photo removed successful";
        }
        throw new NullPointerException("photo not uploaded");

    }

    @Override
    public String deleteRestaurant() throws SessionIdExpiredException {
        checkSession();
        restaurantRepository.deleteById(loggedOwner.getRestaurantId());
        return "restaurant deleted successfully";

    }

    @Override
    public String logout() throws SessionIdExpiredException {
        if (sessionId != null) {
            loggedOwner = null;
            sessionId = null;
            return "sign out successful";
        }
        throw new SessionIdExpiredException("trying to logout without login");
    }


    /**
     * Category functions
     */

    @Override
    public String addCategories(List<Categories> categories) throws SessionIdExpiredException {
        checkSession();
        if (!categories.isEmpty()) {
            for (Categories category : categories)
                jdbcTemplate.update("Insert into categories values (? , ? , ?)", category.getCategoryName(),
                        loggedOwner.getRestaurantId(), category.getDeliveryCharge());
            return "categories added successfully";
        }
        throw new NullPointerException("categories cannot be empty");

    }

    private boolean checkForCategoryExist(String categoryName) {
        return !jdbcTemplate.query("select * from categories where categoryName = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(Categories.class), categoryName, loggedOwner.getRestaurantId()).isEmpty();
    }

    @Override
    public String changeDeliveryCharge(int deliveryCharge, String categoryName) throws SessionIdExpiredException {
        checkSession();
        if (checkForCategoryExist(categoryName))
            jdbcTemplate.update("update categories set deliveryCharge = ? where categoryName = ? and restaurant_id = ?",
                    deliveryCharge, categoryName, loggedOwner.getRestaurantId());
        throw new NullPointerException("category not exist in your restaurant");

    }

    @Override
    public String removeCategory(String categoryName) throws SessionIdExpiredException {
        checkSession();
        if (checkForCategoryExist(categoryName))
            jdbcTemplate.update("delete from categories where categoryName = ? and restaurant_id = ?",
                    categoryName, loggedOwner.getRestaurantId());
        throw new NullPointerException("category not exist in your restaurant");

    }

    @Override
    public List<Categories> viewCategories() throws SessionIdExpiredException {
        checkSession();
        List<Categories> category = jdbcTemplate.query("select * from categories where restaurant_id = ?",
                new BeanPropertyRowMapper<>(Categories.class), loggedOwner.getRestaurantId());
        if (category.isEmpty())
            throw new NullPointerException("Categories not found");
        else return category;
    }

    @Override
    public Categories getParticularCategory(String categoryName) throws SessionIdExpiredException {
        checkSession();
        List<Categories> category = jdbcTemplate.query("select * from categories where categoryName = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(Categories.class), categoryName, loggedOwner.getRestaurantId());
        if (category.isEmpty())
            throw new NullPointerException("no category found");
        else return category.get(0);
    }


    /**
     * Menu functions
     */

    @Override
    public String addMenu(Menu menu, MultipartFile dishPhoto) throws SessionIdExpiredException, IOException {
        checkSession();
        if (menu != null) {
            if (dishPhoto == null) {
                jdbcTemplate.update("Insert into menu values(?,?,?,?,?,?)", menu.getItemName(), menu.getCategoryName(),
                        menu.getDescription(), menu.getItemPrice(), null, loggedOwner.getRestaurantId());
            } else {
                menu.setItemPhoto(dishFilePath + File.separator + dishPhoto.getOriginalFilename());
                dishPhoto.transferTo(Path.of(dishFilePath + File.separator + dishPhoto.getOriginalFilename()));
                jdbcTemplate.update("Insert into menu values(?,?,?,?,?,?)", menu.getItemName(), menu.getCategoryName(),
                        menu.getDescription(), menu.getItemPrice(), menu.getItemPhoto(), loggedOwner.getRestaurantId());
            }
            return "menu added successfully";
        }
        throw new NullPointerException("Menu cannot be null");

    }

    private boolean checkForItemExist(String itemName, String categoryName) {
        return !jdbcTemplate.query("select * from menu where itemName = ? and categoryName = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(Menu.class), itemName, categoryName, loggedOwner.getRestaurantId()).isEmpty();
    }

    @Override
    public String changeDescription(String itemName, String categoryName, String description) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (checkForItemExist(itemName, categoryName)) {
            jdbcTemplate.update("update menu set description = ? where itemName = ? and categoryName = ? and " +
                    "restaurant_id = ?", description, itemName, categoryName, loggedOwner.getRestaurantId());
        }
        throw new UpdateFailedException("Invalid item or category");

    }

    @Override
    public String changeDishPhoto(String itemName, String categoryName, MultipartFile dishPhoto) throws SessionIdExpiredException, UpdateFailedException, IOException {
        checkSession();
        if (dishPhoto != null) {
            if (checkForItemExist(itemName, categoryName)) {
                deleteOldPhoto(itemName, categoryName);
                String setItemPhoto = dishFilePath + File.separator + dishPhoto.getOriginalFilename();
                dishPhoto.transferTo(Path.of(setItemPhoto));
                jdbcTemplate.update("update menu set dishPhoto = ? where itemName = ? and categoryName = ? and " +
                        "restaurant_id = ?", setItemPhoto, itemName, categoryName, loggedOwner.getRestaurantId());
            }
            throw new UpdateFailedException("Invalid item or category");
        }
        throw new NullPointerException("photo is null");

    }

    @Override
    public String deleteOldPhoto(String itemName, String categoryName) throws IOException, SessionIdExpiredException {
        checkSession();
        List<Menu> menu = jdbcTemplate.query("Select * from menu where itemName = ? and categoryName = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(Menu.class), itemName, categoryName, loggedOwner.getRestaurantId());
        String path = menu.get(0).getItemPhoto();
        if (path != null) {
            Files.deleteIfExists(Path.of(path));
            jdbcTemplate.update("Update restaurants set restaurant_photo = ? where restaurant_id = ?",
                    null, loggedOwner.getRestaurantId());
            return "photo deleted successfully";
        }
        throw new NullPointerException("photo not uploaded");

    }

    @Override
    public String changeDishPrice(String itemName, String categoryName, int itemPrice) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (checkForItemExist(itemName, categoryName)) {
            jdbcTemplate.update("update menu set itemPrice = ? where itemName = ? and categoryName = ? and restaurant_id = ?",
                    itemPrice, itemName, categoryName, loggedOwner.getRestaurantId());
        }
        throw new UpdateFailedException("Invalid item or category");

    }

    @Override
    public String changeCategory(String itemName, String oldCategoryName, String newCategoryName) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (checkForItemExist(itemName, oldCategoryName)) {
            jdbcTemplate.update("update menu set categoryName = ? where itemName = ? and categoryName = ? and " +
                    "restaurant_id = ?", newCategoryName, itemName, oldCategoryName, loggedOwner.getRestaurantId());
        }
        throw new UpdateFailedException("Invalid item or category");

    }

    @Override
    public String removeMenu(String itemName, String categoryName) throws UpdateFailedException, SessionIdExpiredException {
        checkSession();
        if (checkForItemExist(itemName, categoryName)) {
            jdbcTemplate.update("delete from menu where itemName = ? and categoryName = ? and " +
                    "restaurant_id = ?", itemName, categoryName, loggedOwner.getRestaurantId());
            return "Item in menu removed successfully";
        }
        throw new UpdateFailedException("Invalid item or category");

    }


    /**
     * Payment Interface
     */


    @Override
    public String updatePaymentType(List<Payment> payments) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (!payments.isEmpty()) {
            for (Payment payment : payments)
                if (paymentTypeExit(payment.getPaymentType()))
                    jdbcTemplate.update("Insert into payment values (? , ? )", payment.getPaymentType(),
                            loggedOwner.getRestaurantId());
            return "payments added successfully";
        }
        throw new UpdateFailedException("null value cannot be updated");

    }

    private boolean paymentTypeExit(String paymentType) {
        return jdbcTemplate.query("Select * from payment where restaurant_id = ? and paymentType = ?",
                new BeanPropertyRowMapper<>(Payment.class), loggedOwner.getRestaurantId(), paymentType).isEmpty();
    }

    @Override
    public String removePaymentType(String paymentType) throws SessionIdExpiredException, UpdateFailedException {
        checkSession();
        if (!paymentTypeExit(paymentType)) {
            jdbcTemplate.update("Delete from payment where restaurant_id = ? and paymentType = ?",
                    loggedOwner.getRestaurantId(), paymentType);
            return "payment type deleted successfully";
        }
        throw new UpdateFailedException("Payment type not found");

    }

    /**
     * RestaurantOrders Interface
     */

    @Override
    public List<RestaurantOrders> viewCurrentDayOrders(String orderId) throws SessionIdExpiredException {
        checkSession();
        List<RestaurantOrders> restaurantOrders = jdbcTemplate.query("Select * from RestaurantOrders where orderId = ?",
                new BeanPropertyRowMapper<>(RestaurantOrders.class), orderId);
        if (restaurantOrders.isEmpty())
            throw new NullPointerException("no orders placed with this id");
        else return restaurantOrders;
    }

    @Override
    public List<RestaurantOrders> viewPastOrders(LocalDate date) throws SessionIdExpiredException {
        checkSession();
        return null;
    }

    @Override
    public List<RestaurantOrders> viewAllOrders() throws SessionIdExpiredException {
        checkSession();
        List<RestaurantOrders> restaurantOrders = jdbcTemplate.query("Select * from RestaurantOrders where restaurant_id = ?",
                new BeanPropertyRowMapper<>(RestaurantOrders.class),loggedOwner.getRestaurantId());
        if (restaurantOrders.isEmpty())
            throw new NullPointerException("no orders placed for your restaurant");
        else return restaurantOrders;
    }
}
