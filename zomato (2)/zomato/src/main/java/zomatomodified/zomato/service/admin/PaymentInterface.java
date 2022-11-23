package zomatomodified.zomato.service.admin;

import zomatomodified.zomato.coustomexcptions.UpdateFailedException;
import zomatomodified.zomato.model.Payment;

import java.util.List;

public interface PaymentInterface {

    String updatePaymentType(List<Payment> payments,String restaurantId) throws UpdateFailedException;

    String removePaymentType(String paymentType,String restaurantId) throws UpdateFailedException;

}
