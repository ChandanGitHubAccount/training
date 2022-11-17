package zomato.service.restaurant;

import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.InvalidTimeException;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.coustomexcptions.UpdateFailedException;
import zomato.entity.Restaurants;

import java.io.IOException;
import java.time.LocalTime;

public interface RestaurantInterface {

    String Login(String restaurantId) throws SessionIdExpiredException;

    String register(String restaurantId, String restaurantName, String restaurantAddress, LocalTime openAt, LocalTime closeAt, String closeOn, MultipartFile photo) throws IOException, SessionIdExpiredException;

    Restaurants viewRestaurantDetails() throws SessionIdExpiredException;

    byte[] viewRestaurantPhoto() throws SessionIdExpiredException, IOException;
    String changeRestaurantPhoto(MultipartFile photo) throws IOException, SessionIdExpiredException, UpdateFailedException;

    String changeOpenTime(int openHour, int openMinutes) throws SessionIdExpiredException, InvalidTimeException;

    String changeCloseTime(int closeHour, int closeMinutes) throws SessionIdExpiredException, InvalidTimeException;

    String changeCloseDay(String day) throws SessionIdExpiredException, UpdateFailedException;

    String changeRestaurantAddress(String restaurantAddress) throws SessionIdExpiredException, UpdateFailedException;

    String changeRestaurantName(String restaurantName) throws SessionIdExpiredException, UpdateFailedException;

    String deleteRestaurantPhoto() throws SessionIdExpiredException, IOException;

    String deleteRestaurant() throws SessionIdExpiredException;

    String logout() throws SessionIdExpiredException;
}
