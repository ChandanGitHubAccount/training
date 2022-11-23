package zomatomodified.zomato.service.admin;

import zomatomodified.zomato.entity.Categories;
import zomatomodified.zomato.model.RestaurantCategory;

import java.util.List;

public interface MenuCategoryInterface {

    String addMenu(List<String> categoryId, String restaurantId);

    String deleteMenu(String restaurantId);

    String deleteCategory(String categoryId, String restaurantId);

    List<RestaurantCategory> viewMenu(String restaurantId);

    List<Categories> viewAllCategories();
}
