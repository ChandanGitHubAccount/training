package zomatomodified.zomato.customannottaton;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.List;

public class TokenStatusValidator implements ConstraintValidator<TokenStatus,String > {
    @Override
    public boolean isValid(String tokenStatus, ConstraintValidatorContext constraintValidatorContext) {
        List<String> genderList = Arrays.asList("ACTIVE", "EXPIRED");
        return genderList.contains(tokenStatus.toUpperCase());
    }
}
