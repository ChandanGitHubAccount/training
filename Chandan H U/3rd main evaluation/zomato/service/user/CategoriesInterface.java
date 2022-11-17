package zomato.service.user;

import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Categories;

import java.util.List;

public interface CategoriesInterface {
    List<Categories> showAllCategoriesOfRestaurant(String restaurantId, int pageSize, int pageNumber) throws SessionIdExpiredException;

}
