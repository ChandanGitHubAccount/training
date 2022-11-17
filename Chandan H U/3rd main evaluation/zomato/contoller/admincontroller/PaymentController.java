package zomato.contoller.admincontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.coustomexcptions.UpdateFailedException;
import zomato.model.Payment;
import zomato.service.restaurant.PaymentInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/restaurant")
public class PaymentController {

    /**
     * Payment Controller
     */

    @Autowired
    private PaymentInterface paymentInterface;

    @DeleteMapping("/remove-payment-type")
    public ResponseEntity<String> removePaymentType(@RequestParam String paymentType) throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(paymentInterface.removePaymentType(paymentType)));
    }

    @PostMapping("/add-payment-types")
    public ResponseEntity<String> updatePaymentType(@RequestBody List<Payment> payments) throws SessionIdExpiredException, UpdateFailedException {
        return ResponseEntity.of(Optional.of(paymentInterface.updatePaymentType(payments)));
    }

}
