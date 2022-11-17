package zomato.customannottaton;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CardValidator implements ConstraintValidator<Card,Long> {
    @Override
    public boolean isValid(Long cardNumber, ConstraintValidatorContext constraintValidatorContext) {
        return Long.toString(cardNumber).length() == 12;
    }
}
