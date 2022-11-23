package zomatomodified.zomato.controlller.admin;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.coustomexcptions.UpdateFailedException;
import zomatomodified.zomato.model.Payment;
import zomatomodified.zomato.service.admin.PaymentInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/admin")
public class PaymentController {

    @Autowired
    private PaymentInterface paymentInterface;

    @PostMapping("/add-payment")
    public ResponseEntity<String> addPaymentTypes(@RequestBody List<Payment> payments, @RequestParam String restaurantId) throws UpdateFailedException {
        return ResponseEntity.of(Optional.of(paymentInterface.updatePaymentType(payments, restaurantId)));
    }

    @DeleteMapping("/remove-payment")
    public ResponseEntity<String> removePaymentType(@RequestPart String paymentType, @RequestPart String restaurantId) throws UpdateFailedException {
        return ResponseEntity.of(Optional.of(paymentInterface.removePaymentType(paymentType, restaurantId)));
    }

}
