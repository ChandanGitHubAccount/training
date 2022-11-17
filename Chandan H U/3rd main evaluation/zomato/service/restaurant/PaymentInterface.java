package zomato.service.restaurant;

import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.coustomexcptions.UpdateFailedException;
import zomato.model.Payment;

import java.util.List;

public interface PaymentInterface {

    String updatePaymentType(List<Payment> payments) throws SessionIdExpiredException, UpdateFailedException;

    String removePaymentType(String paymentType) throws SessionIdExpiredException, UpdateFailedException;
}
