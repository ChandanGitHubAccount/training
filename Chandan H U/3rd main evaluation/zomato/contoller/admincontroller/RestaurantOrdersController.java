package zomato.contoller.admincontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.RestaurantOrders;
import zomato.service.restaurant.RestaurantOrdersInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/restaurant")
public class RestaurantOrdersController {

    /**
     * RestaurantOrders controller
     */

    @Autowired
    private RestaurantOrdersInterface restaurantOrdersInterface;

    @GetMapping("/get-orders")
    public ResponseEntity<List<RestaurantOrders>> getOrder(@RequestParam String orderId) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantOrdersInterface.viewCurrentDayOrders(orderId)));
    }

    @GetMapping("/view-all-orders")
    public ResponseEntity<List<RestaurantOrders>> getAllOrder() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(restaurantOrdersInterface.viewAllOrders()));
    }

}
