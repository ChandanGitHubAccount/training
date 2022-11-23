package zomatomodified.zomato.customannottaton;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class PhoneNumberValidator implements ConstraintValidator<PhoneNumber,Long> {
    @Override
    public boolean isValid(Long phoneNumber, ConstraintValidatorContext constraintValidatorContext) {
        return Long.toString(phoneNumber).length() == 10;
    }
}
