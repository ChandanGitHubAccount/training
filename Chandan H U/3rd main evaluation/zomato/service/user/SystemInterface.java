package zomato.service.user;

import zomato.coustomexcptions.EmailValidationException;
import zomato.coustomexcptions.OTPGenerateException;
import zomato.coustomexcptions.SessionIdExpiredException;

public interface SystemInterface {

    String generateId();

    int generateOTP();

    String verifyEmail(int otp) throws OTPGenerateException, EmailValidationException, SessionIdExpiredException;

    String sendOTP() throws SessionIdExpiredException, OTPGenerateException;

    boolean verifyCard(long cardNumber);

    boolean verifyOrderId(String orderId);

    boolean verifyPaymentAvailability(String restaurantId, String paymentType) throws SessionIdExpiredException;

    void checkSession() throws SessionIdExpiredException;
}
