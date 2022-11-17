package zomato.service.user;

import org.springframework.data.domain.Page;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.entity.Restaurants;
import zomato.model.Categories;

import java.io.IOException;
import java.util.List;

public interface HomeInterface {

    Page<Restaurants> topRatedRestaurants(int pageNumber, int pageSize) throws SessionIdExpiredException;

    List<Categories> viewCategories(int pageNumber, int pageSize) throws SessionIdExpiredException;

    byte[] viewRestaurantPhoto(String restaurantId) throws SessionIdExpiredException, IOException;
}
