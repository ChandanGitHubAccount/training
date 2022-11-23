package zomatomodified.zomato.controlller.admin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.model.RestaurantOrders;
import zomatomodified.zomato.service.admin.RestaurantOrderInterface;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/admin")
public class RestaurantOrderController {

    @Autowired
    private RestaurantOrderInterface restaurantOrderInterface;

    @GetMapping("/get-orders")
    public ResponseEntity<List<RestaurantOrders>> getOrder(@RequestPart String orderId) {
        return ResponseEntity.of(Optional.of(restaurantOrderInterface.viewCurrentDayOrders(orderId)));
    }

    @GetMapping("/view-all-orders")
    public ResponseEntity<List<RestaurantOrders>> getAllOrder(@RequestPart String restaurantId) {
        return ResponseEntity.of(Optional.of(restaurantOrderInterface.viewAllOrders(restaurantId)));
    }

    @GetMapping("/view-by-date")
    public ResponseEntity<List<RestaurantOrders>> getByDate(@RequestPart String restaurantId, @RequestParam @DateTimeFormat
            (iso = DateTimeFormat.ISO.DATE) LocalDate ordersDate) {
        return ResponseEntity.of(Optional.of(restaurantOrderInterface.viewOrdersByDate(ordersDate, restaurantId)));
    }

}
