package zomato.contoller.usercontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomato.coustomexcptions.InvalidCardNumberException;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.MyOrders;
import zomato.service.user.OrderInterface;

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
    public ResponseEntity<List<MyOrders>> addOrders(@RequestParam String restaurantId, @RequestBody Map<String, Map<String, Integer>> orders,
                                                    @RequestParam String paymentType) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(orderInterface.addOrders(restaurantId, orders, paymentType)));
    }

    @PostMapping("/make-payment")
    public ResponseEntity<String > makePayment(@RequestParam String restaurantId,@RequestParam String orderId,
                                               @RequestParam String paymentType,@RequestParam(required = false) Long cardNumber) throws SessionIdExpiredException, InvalidCardNumberException{
        return ResponseEntity.of(Optional.of(orderInterface.makePayment(restaurantId,orderId,paymentType,cardNumber)));
    }
}
