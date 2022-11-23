package zomatomodified.zomato.service.system;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import zomatomodified.zomato.coustomexcptions.EmailValidationException;
import zomatomodified.zomato.entity.Users;
import zomatomodified.zomato.model.*;
import zomatomodified.zomato.repository.UserRepository;
import zomatomodified.zomato.service.AccountStatus;

import java.util.List;
import java.util.Random;

@Service
public class SystemService implements SystemInterface {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private UserRepository userRepository;

    @Override
    public String generateId() {
        Random random = new Random();
        StringBuilder id = new StringBuilder();
        for (int index = 0; index < 4; index++) {
            char character = (char) (65 + random.nextInt(26));
            try {
                id.append(character);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        for (int index = 0; index < 6; index++) {
            char number = (char) (48 + random.nextInt(10));
            try {
                id.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return id.toString();
    }

    @Override
    public int generateOTP() {
        Random random = new Random();
        StringBuilder otp = new StringBuilder();
        for (int index = 0; index < 6; index++) {
            char number = (char) (48 + random.nextInt(10));
            try {
                otp.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return Integer.parseInt(otp.toString());
    }

    @Override
    public String verifyEmail(int userOTP, String email) throws EmailValidationException {
        if (userOTP == getOtp(email).get(0).getOtp()) {
            jdbcTemplate.update("update users set account_status = ?", AccountStatus.VERIFIED.toString());
            return "Email verified successfully";
        }
        throw new EmailValidationException("Incorrect OTP");
    }

    private List<OTPManager> getOtp(String email) {
        return jdbcTemplate.query("Select * from otpManager where email = ?",
                new BeanPropertyRowMapper<>(OTPManager.class), email);
    }

    @Override
    public String sendOTP(String userEmail) {
        Users user = userRepository.findByEmail(userEmail).get(0);
        List<OTPManager> otpManager = getOtp(userEmail);
        if (otpManager.isEmpty()) {
            int otp = generateOTP();
            SimpleMailMessage email = new SimpleMailMessage();
            email.setFrom("raspberrypi001025@gmail.com");
            email.setTo(userEmail);
            email.setSubject("OTP");
            email.setText("Enter the OTP to verify the account\n" + otp);
            javaMailSender.send(email);
            jdbcTemplate.update("Insert into OTPManager values (? , ? , ?)", user.getUserId(), userEmail, otp);
        } else {
            SimpleMailMessage email = new SimpleMailMessage();
            email.setFrom("raspberrypi001025@gmail.com");
            email.setTo(userEmail);
            email.setSubject("OTP");
            email.setText("Enter the OTP to verify the account\n" + otpManager.get(0).getOtp());
            javaMailSender.send(email);
        }
        return "OTP sent Successfully";
    }

    @Override
    public boolean verifyCard(long cardNumber, String userId) {
        return jdbcTemplate.query("select * from cards where cardNumber = ? and user_id = ?",
                new BeanPropertyRowMapper<>(Cards.class), cardNumber, userId).isEmpty();
    }

    @Override
    public boolean verifyOrderId(String orderId) {
        return jdbcTemplate.query("select * from myOrderItems where orderId = ? ",
                new BeanPropertyRowMapper<>(MyOrderItems.class), orderId).isEmpty();
    }

    @Override
    public boolean checkAvailabilityOfEmail(String email) {
        return userRepository.findByEmail(email).isEmpty();
    }

    @Override
    public boolean checkForDuplicateRegistration(String email, long phoneNumber) {
        return userRepository.findByEmailOrPhoneNumber(email, phoneNumber).isEmpty();
    }

    @Override
    public boolean verifyPaymentAvailability(String restaurantId, String paymentType) {
        return !jdbcTemplate.query("Select * from restaurantPayments where paymentType = ? and restaurant_id = ?",
                new BeanPropertyRowMapper<>(Payment.class), paymentType, restaurantId).isEmpty();

    }

    @Override
    public boolean verifyGstNumber(String gstNumber) {
        String REGEX = "^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$";
        return gstNumber.matches(REGEX);
    }

    @Override
    public boolean verifyDishId(String itemId) {
        return !jdbcTemplate.query("select * from dish where itemId = ?", new BeanPropertyRowMapper<>(Dish.class),
                itemId).isEmpty();
    }

    @Override
    public boolean paymentTypeExit(String paymentType, String restaurantId) {
        return jdbcTemplate.query("Select * from restaurantPayments where restaurant_id = ? and paymentType = ?",
                new BeanPropertyRowMapper<>(Payment.class), restaurantId, paymentType).isEmpty();
    }
}
