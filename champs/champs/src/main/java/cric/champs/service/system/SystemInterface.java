package cric.champs.service.system;

import cric.champs.customexceptions.EmailValidationException;
import cric.champs.entity.ResultModel;
import cric.champs.customexceptions.OTPGenerateException;
import cric.champs.entity.Users;
import io.jsonwebtoken.impl.DefaultClaims;

import java.util.List;
import java.util.Map;

public interface SystemInterface {

    int generateOTP();

    boolean verifyEmail(String email);

    ResultModel verifyUserAccount(int otp, String email) throws EmailValidationException;

    ResultModel sendOTP(String email) throws OTPGenerateException;

    long getUserId();

    List<Users> getUserDetails(String email , String accountStatus);

    Users getUserDetailByUserId();

    Map<String, Object> getMapFromDefaultClaim(DefaultClaims claims);
}
