package zomatomodified.zomato.service.user;

import zomatomodified.zomato.entity.Categories;

import java.util.List;

public interface CategoriesInterface {

    List<Categories> showAllCategoriesOfRestaurant(String restaurantId, int pageSize, int pageNumber);

}
