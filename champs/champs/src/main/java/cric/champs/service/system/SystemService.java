package cric.champs.service.system;

import cric.champs.customexceptions.EmailValidationException;
import cric.champs.entity.ResultModel;
import cric.champs.customexceptions.OTPGenerateException;
import cric.champs.entity.Users;
import cric.champs.entity.OTPManager;
import cric.champs.service.AccountStatus;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class SystemService implements SystemInterface {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private JavaMailSender javaMailSender;

    @Override
    public int generateOTP() {
        return new Random().nextInt(100000, 1000000);
    }

    @Override
    public boolean verifyEmail(String email) {
        return jdbcTemplate.query("select * from users where email = ? and isDelete = 'false'",
                new BeanPropertyRowMapper<>(Users.class), email).isEmpty();
    }

    @Override
    public ResultModel verifyUserAccount(int otp, String email) throws EmailValidationException {
        if (otp == getOtp(email).get(0).getOtp()) {
            jdbcTemplate.update("update users set account_status = ?", AccountStatus.VERIFIED.toString());
            return new ResultModel("Email verified successfully");
        }
        throw new EmailValidationException("Incorrect OTP");
    }

    private List<OTPManager> getOtp(String email) {
        return jdbcTemplate.query("Select * from otpManager where email = ?",
                new BeanPropertyRowMapper<>(OTPManager.class), email);
    }

    @Override
    public ResultModel sendOTP(String userEmail) throws OTPGenerateException {
        List<Users> user = getUserDetails(userEmail, AccountStatus.NOTVERIFIED.toString());

        if (user.isEmpty())
            throw new OTPGenerateException("enter valid registered email");
        List<OTPManager> otpManager = getOtp(userEmail);
        int otp = generateOTP();
        if (otpManager.isEmpty())
            jdbcTemplate.update("Insert into OTPManager values (? , ? , ? , ?)", user.get(0).getUserId(), userEmail,
                    otp, LocalTime.now().plusMinutes(5));
        else
            jdbcTemplate.update("update OTPManager set otp = ? and expireAt = ? where email = ?", otp, userEmail,
                    LocalTime.now().plusMinutes(5));

        SimpleMailMessage email = new SimpleMailMessage();
        email.setFrom("raspberrypi001025@gmail.com");
        email.setTo(userEmail);
        email.setSubject("Cric champs registration OTP");
        email.setText("Enter otp in Cric Champs application to verify the account\n" + otp);
        javaMailSender.send(email);

        return new ResultModel("OTP sent Successfully");
    }

    @Override
    public long getUserId() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return getUserDetails(userDetails.getUsername(), AccountStatus.VERIFIED.toString()).get(0).getUserId();
    }

    @Override
    public List<Users> getUserDetails(String email, String accountStatus) {
        return jdbcTemplate.query("select * from users where email = ? and accountStatus = ?" +
                " and isDelete = 'false'", new BeanPropertyRowMapper<>(Users.class), email, accountStatus);
    }

    @Override
    public Users getUserDetailByUserId() {
        return jdbcTemplate.query("select * from users where userId = ?  and isDelete = 'false'",
                new BeanPropertyRowMapper<>(Users.class), getUserId()).get(0);
    }

    @Override
    public Map<String, Object> getMapFromDefaultClaim(DefaultClaims claims) {
        return new HashMap<>(claims);
    }
}
