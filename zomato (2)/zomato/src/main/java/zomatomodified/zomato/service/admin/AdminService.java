package zomatomodified.zomato.service.admin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import zomatomodified.zomato.coustomexcptions.UpdateFailedException;
import zomatomodified.zomato.entity.Categories;
import zomatomodified.zomato.model.*;
import zomatomodified.zomato.repository.CategoryRepository;
import zomatomodified.zomato.service.system.LoggedUser;
import zomatomodified.zomato.service.system.SystemInterface;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;

@Service
public class AdminService implements RestaurantInterface, MenuInterface, MenuCategoryInterface, DishInterface, PaymentInterface, RestaurantOrderInterface {
    private static final String restaurantFilePath = "C:\\Users\\Chandan H U\\Desktop\\restaurantPhoto";

    private static final String dishFilePath = "C:\\Users\\Chandan H U\\Desktop\\dishPhoto";

    @Autowired
    private SystemInterface systemInterface;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private LoggedUser loggedUser;


    /**
     * Restaurant functions
     */

    @Override
    public String register(String restaurantName, String restaurantAddress, LocalTime openAt, LocalTime closeAt,
                           String closeOn, int deliveryCharge, MultipartFile photo) throws IOException {
        String restaurantId = systemInterface.generateId();
        String restaurantPhoto = null;
        List<Restaurants> restaurants = jdbcTemplate.query("select * from restaurants where restaurant_id = ?",
                new BeanPropertyRowMapper<>(Restaurants.class), restaurantId);
        if (!restaurants.isEmpty())
            register(restaurantName, restaurantAddress, openAt, closeAt, closeOn, deliveryCharge, photo);


        if (photo.getOriginalFilename() != null) {
            restaurantPhoto = restaurantFilePath + File.separator + photo.getOriginalFilename();
            photo.transferTo(Path.of(restaurantPhoto));
        }
        jdbcTemplate.update("insert into restaurants values(?,?,?,?,?,?,?,?,?,?,?)", restaurantId, loggedUser.getUsers().getUserId(),
                restaurantAddress, restaurantName, openAt, closeAt, closeOn, 0, deliveryCharge, "false", restaurantPhoto);

        return "restaurant added successfully";
    }

    @Override
    public List<Restaurants> viewRestaurantDetails() {

        return jdbcTemplate.query("select * from restaurants where user_id = ?",
                new BeanPropertyRowMapper<>(Restaurants.class), loggedUser.getUsers().getUserId());
    }

    @Override
    public byte[] viewRestaurantPhoto(String restaurantId) throws IOException {
        String path = viewParticularRestaurantDetails(restaurantId).getRestaurantPhoto();
        if (path != null)
            return Files.readAllBytes(Path.of(path));
        throw new NullPointerException("Restaurant image not uploaded");
    }

    @Override
    public String changeRestaurantPhoto(String restaurantId, MultipartFile photo) throws IOException, UpdateFailedException {
        if (photo.getOriginalFilename() != null) {
            deleteRestaurantPhoto(restaurantId);
            String setRestaurantPhoto = restaurantFilePath + File.separator + photo.getOriginalFilename();
            jdbcTemplate.update("update restaurants set restaurant_photo = ? where restaurant_id = ?",
                    setRestaurantPhoto, restaurantId);
            photo.transferTo(Path.of(setRestaurantPhoto));
            return "Photo uploaded successfully";
        }
        throw new UpdateFailedException("Select proper picture");
    }


    @Override
    public String deleteRestaurantPhoto(String restaurantId) throws IOException {
        String path = viewParticularRestaurantDetails(restaurantId).getRestaurantPhoto();
        if (path != null) {
            Files.deleteIfExists(Path.of(path));
            jdbcTemplate.update("Update restaurants set restaurant_photo = ? where restaurant_id = ?",
                    null, restaurantId);
            return "photo removed successful";
        }
        return "photo not uploaded";
    }

    @Override
    public String deleteRestaurant(String restaurantId) {
        if (viewParticularRestaurantDetails(restaurantId) != null) {
            jdbcTemplate.update("delete from restaurants where restaurant_id = ?", restaurantId);
            return "restaurant deleted successfully";
        }
        throw new NullPointerException("restaurant not found");

    }

    @Override
    public String editRestaurant(Restaurants restaurant) {
        jdbcTemplate.update("update Restaurants set restaurant_address = ?,restaurant_name = ?,open_at = ?,close_at = ?," +
                        "close_on = ? , delivery_charge = ? where restaurant_id = ? and user_id = ?",
                restaurant.getRestaurantAddress(), restaurant.getRestaurantName(), restaurant.getOpenAt(),
                restaurant.getCloseAt(), restaurant.getCloseOn(), restaurant.getDeliveryCharge(), restaurant.getRestaurantId(),
                loggedUser.getUsers().getUserId());
        return "updated successfully";
    }

    @Override
    public Restaurants viewParticularRestaurantDetails(String restaurantId) {
        List<Restaurants> restaurants = jdbcTemplate.query("Select * from restaurants where restaurant_id = ?",
                new BeanPropertyRowMapper<>(Restaurants.class), restaurantId);
        return restaurants.isEmpty() ? null : restaurants.get(0);
    }


    /**
     * *****Menu Interface *****
     */


    @Override
    public String addMenu(List<String> categoryId, String restaurantId) {
        for (String category : categoryId)
            if (!categoryRepository.findByCategoryId(category).isEmpty())
                jdbcTemplate.update("insert restaurantCategory values(?,?)", category, restaurantId);
        return "menu added successfully";
    }

    @Override
    public String deleteMenu(String restaurantId) {
        if (viewParticularRestaurantDetails(restaurantId) != null) {
            jdbcTemplate.update("delete from menu where restaurant_id = ?", restaurantId);
            return "menu deleted successfully";
        }
        throw new NullPointerException("restaurant not found");
    }

    @Override
    public String deleteCategory(String categoryId, String restaurantId) {
        if (viewMenuOfCategoryAndRestaurant(categoryId, restaurantId) != null) {
            jdbcTemplate.update("delete from restaurantCategory where category_id = ? and restaurant_id = ?", categoryId, restaurantId);
            return "category deleted successfully";
        }
        throw new NullPointerException("Menu not found with entered category or restaurant");
    }

    @Override
    public List<RestaurantCategory> viewMenu(String restaurantId) {
        return jdbcTemplate.query("select * from restaurantCategory where restaurant_id = ?",
                new BeanPropertyRowMapper<>(RestaurantCategory.class), restaurantId);
    }

    @Override
    public List<Categories> viewAllCategories() {
        return categoryRepository.findAll();
    }

    private RestaurantCategory viewMenuOfCategoryAndRestaurant(String categoryId, String restaurantId) {
        List<RestaurantCategory> restaurantCategories = jdbcTemplate.query("select * from restaurantCategory where category_id = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(RestaurantCategory.class), categoryId, restaurantId);
        return restaurantCategories.isEmpty() ? null : restaurantCategories.get(0);
    }


    /**
     * *****Dish Interface *****
     */

    @Override
    public String addDish(List<Dish> dish) {
        if (dish.isEmpty())
            throw new NullPointerException("empty items cannot be added");
        for (Dish item : dish) {
            String itemId = systemInterface.generateId();
            if (systemInterface.verifyDishId(itemId))
                addDish(dish);
            jdbcTemplate.update("insert into Dish values(?,?,?,?,?,?,?)", itemId, item.getRestaurantId(),
                    item.getCategoryId(), item.getItemName(), item.getItemPrice(), item.getDescription(), null);
        }
        return "food items added successfully";
    }

    @Override
    public String editDish(Dish dish) throws UpdateFailedException {
        if (dish != null) {
            jdbcTemplate.update("update dish set itemName = ?, itemPrice = ?, description = ? where itemId = ?",
                    dish.getItemName(), dish.getItemPrice(), dish.getDescription(), dish.getItemId());
            return "update successful";
        }
        throw new UpdateFailedException("update failed");
    }

    @Override
    public String changeDishPhoto(String itemId, MultipartFile dishPhoto) throws UpdateFailedException, IOException {
        if (dishPhoto != null) {
            if (systemInterface.verifyDishId(itemId)) {
                deleteDishPhoto(itemId);
                String setItemPhoto = dishFilePath + File.separator + dishPhoto.getOriginalFilename();
                dishPhoto.transferTo(Path.of(setItemPhoto));
                jdbcTemplate.update("update dish set itemPhoto = ? where itemId = ? ", setItemPhoto, itemId);
                return "photo updated successfully";
            }
            throw new UpdateFailedException("Invalid item id");
        }
        throw new NullPointerException("photo is null");
    }

    @Override
    public String removeDish(String itemId) throws UpdateFailedException {
        if (systemInterface.verifyDishId(itemId)) {
            jdbcTemplate.update("delete from dish where itemId = ?", itemId);
            return "removed successfully";
        }
        throw new UpdateFailedException("Invalid item id");
    }

    @Override
    public String deleteDishPhoto(String itemId) throws IOException {
        String path = jdbcTemplate.query("Select * from dish where itemId = ?",
                new BeanPropertyRowMapper<>(Dish.class), itemId).get(0).getItemPhoto();
        if (path != null) {
            Files.deleteIfExists(Path.of(path));
            jdbcTemplate.update("Update dish set itemPhoto = ? where itemId = ?", null, itemId);
            return "photo deleted successfully";
        }
        return "photo not uploaded";
    }


    /**
     * Payment Interface
     */

    @Override
    public String updatePaymentType(List<Payment> payments, String restaurantId) throws UpdateFailedException {
        StringBuilder result = new StringBuilder("payments added successfully");
        if (!payments.isEmpty()) {
            for (Payment payment : payments) {
                if (systemInterface.paymentTypeExit(payment.getPaymentType(), restaurantId))
                    jdbcTemplate.update("Insert into restaurantPayments values (? , ? )", payment.getPaymentType(),
                            restaurantId);
                else result.append("\npayment type : ").append(payment.getPaymentType()).append(" is already added");
            }
            return result.toString();
        }
        throw new UpdateFailedException("select at least one of payment type");

    }

    @Override
    public String removePaymentType(String paymentType, String restaurantId) throws UpdateFailedException {
        if (!systemInterface.paymentTypeExit(paymentType, restaurantId)) {
            jdbcTemplate.update("Delete from restaurantPayments where restaurant_id = ? and paymentType = ?",
                    restaurantId, paymentType);
            return "payment type deleted successfully";
        }
        throw new UpdateFailedException("Payment type not found");

    }


    /**
     * Restaurant Orders Interface
     */

    @Override
    public List<RestaurantOrders> viewCurrentDayOrders(String orderId) {
        List<RestaurantOrders> restaurantOrders = jdbcTemplate.query("Select * from restaurantOrders where orderId = ?",
                new BeanPropertyRowMapper<>(RestaurantOrders.class), orderId);
        if (restaurantOrders.isEmpty())
            throw new NullPointerException("no orders placed with this id");
        else return restaurantOrders;
    }

    @Override
    public List<RestaurantOrders> viewOrdersByDate(LocalDate date, String restaurantId) {
        List<RestaurantOrders> restaurantOrders = jdbcTemplate.query("Select * from restaurantOrders where orderDate  = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(RestaurantOrders.class), date, restaurantId);
        if (restaurantOrders.isEmpty())
            throw new NullPointerException("no orders placed on this date");
        else return restaurantOrders;
    }

    @Override
    public List<RestaurantOrders> viewAllOrders(String restaurantId) {
        List<RestaurantOrders> restaurantOrders = jdbcTemplate.query("Select * from restaurantOrders where restaurant_id = ?",
                new BeanPropertyRowMapper<>(RestaurantOrders.class), restaurantId);
        if (restaurantOrders.isEmpty())
            throw new NullPointerException("no orders placed for your restaurant");
        else return restaurantOrders;
    }

    @Override
    public String addMenu(Menu menu) {
        List<Menu> menus = jdbcTemplate.query("select * from menu where restaurant_id = ?",
                new BeanPropertyRowMapper<>(Menu.class), menu.getRestaurant_id());
        if (!menus.isEmpty())
            return "menu already added";
        String menuId = systemInterface.generateId();
        if (!jdbcTemplate.query("select * from menu where menuId = ?",
                new BeanPropertyRowMapper<>(Menu.class), menu.getRestaurant_id()).isEmpty())
            addMenu(menu);
        jdbcTemplate.update("insert into menu values(?,?,?)", menuId, menu.getMenuName(), menu.getRestaurant_id());
        return "menu added successfully";
    }
}
