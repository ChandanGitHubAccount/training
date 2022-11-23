package zomatomodified.zomato.service.user;

import zomatomodified.zomato.model.Dish;

import java.util.List;

public interface DishInterface {

    List<Dish> viewDishOfRestaurant(String restaurantId, int pageSize, int pageNumber);

    List<Dish> viewDishOfCategory(String categoryId, int pageSize, int pageNumber);

    Dish getDishDetails(String itemId);

}
