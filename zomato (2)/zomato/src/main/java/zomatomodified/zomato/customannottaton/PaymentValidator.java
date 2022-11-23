package zomatomodified.zomato.customannottaton;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.List;

public class PaymentValidator implements ConstraintValidator<Payments,String > {
    @Override
    public boolean isValid(String paymentType, ConstraintValidatorContext constraintValidatorContext) {
        List<String> paymentList = Arrays.asList("CREDITCARD" ,"DEBITCARD","CASHONDELIVARY","UPI","NETBANKING");
        return paymentList.contains(paymentType.toUpperCase());
    }
}
