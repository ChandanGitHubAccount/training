package zomatomodified.zomato.service.system;

import zomatomodified.zomato.coustomexcptions.EmailValidationException;
import zomatomodified.zomato.coustomexcptions.OTPGenerateException;
import zomatomodified.zomato.coustomexcptions.SessionIdExpiredException;

public interface SystemInterface {

    String generateId();

    int generateOTP();

    boolean checkAvailabilityOfEmail(String email);
    boolean checkForDuplicateRegistration(String email, long phoneNumber);

    String verifyEmail(int otp, String email) throws OTPGenerateException, EmailValidationException, SessionIdExpiredException;

    String sendOTP(String email) throws SessionIdExpiredException, OTPGenerateException;

    boolean verifyCard(long cardNumber, String userId);

    boolean verifyOrderId(String orderId);

    boolean verifyPaymentAvailability(String restaurantId, String paymentType);

    boolean verifyGstNumber(String gstNumber);

    boolean verifyDishId(String itemId);

    boolean paymentTypeExit(String paymentType, String restaurantId);

}
