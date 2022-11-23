package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.coustomexcptions.InvalidCardNumberException;
import zomatomodified.zomato.coustomexcptions.SessionIdExpiredException;
import zomatomodified.zomato.model.MyOrders;
import zomatomodified.zomato.service.user.OrderInterface;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/user/order")
public class OrderController {


    /**
     * ******Order Controller******
     */

    @Autowired
    private OrderInterface orderInterface;

    @PostMapping("/place-order")
    public ResponseEntity<List<MyOrders>> addOrders(@RequestHeader String restaurantId, @RequestBody Map<String, Map<String, Integer>> orders,
                                                    @RequestHeader String paymentType) {
        return ResponseEntity.of(Optional.of(orderInterface.addOrders(restaurantId, orders, paymentType)));
    }

    @PostMapping("/make-payment")
    public ResponseEntity<String > makePayment(@RequestPart String restaurantId,@RequestPart String orderId,
                                               @RequestHeader String paymentType,@RequestHeader(required = false) Long cardNumber) throws InvalidCardNumberException {
        return ResponseEntity.of(Optional.of(orderInterface.makePayment(restaurantId,orderId,paymentType,cardNumber)));
    }
}
