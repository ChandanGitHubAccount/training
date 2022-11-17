package zomato.service.user;

import zomato.coustomexcptions.InvalidCardNumberException;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.MyOrders;

import java.util.List;
import java.util.Map;

public interface OrderInterface {

    List<MyOrders> addOrders(String restaurantId, Map<String, Map<String, Integer>> orders, String paymentType) throws SessionIdExpiredException;

    String makePayment(String restaurantId, String orderId, String paymentType, Long cardNumber) throws SessionIdExpiredException, InvalidCardNumberException;
}
