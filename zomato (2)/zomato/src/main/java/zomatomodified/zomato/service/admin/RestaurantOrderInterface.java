package zomatomodified.zomato.service.admin;

import zomatomodified.zomato.model.RestaurantOrders;

import java.time.LocalDate;
import java.util.List;

public interface RestaurantOrderInterface {

    List<RestaurantOrders> viewCurrentDayOrders(String orderId);

    List<RestaurantOrders> viewOrdersByDate(LocalDate date,String restaurantId);

    List<RestaurantOrders> viewAllOrders(String restaurantId);

}
