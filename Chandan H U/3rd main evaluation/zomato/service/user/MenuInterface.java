package zomato.service.user;

import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Menu;

import java.util.List;

public interface MenuInterface {
    List<Menu> viewMenuOfRestaurant(String restaurantId, String categoryName, int pageSize, int pageNumber) throws SessionIdExpiredException;

    List<Menu> viewMenuOfCategory(String categoryName, int pageSize, int pageNumber) throws SessionIdExpiredException;

    Menu getDishDetails(String restaurantId, String categoryName ,String itemName);
}
