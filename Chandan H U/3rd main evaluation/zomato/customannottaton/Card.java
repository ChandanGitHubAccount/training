package zomato.customannottaton;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE, ElementType.CONSTRUCTOR, ElementType.PARAMETER, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Constraint(validatedBy = CardValidator.class)
public @interface Card {

    public String message() default "Please provide valid 12 digit card number";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

}
