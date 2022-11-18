package zomato.service.restaurant;

import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.RestaurantOrders;

import java.time.LocalDate;
import java.util.List;

public interface RestaurantOrdersInterface {

    List<RestaurantOrders> viewCurrentDayOrders(String orderId) throws SessionIdExpiredException;

    List<RestaurantOrders> viewPastOrders(LocalDate date) throws SessionIdExpiredException;

    List<RestaurantOrders> viewAllOrders() throws SessionIdExpiredException;

}
