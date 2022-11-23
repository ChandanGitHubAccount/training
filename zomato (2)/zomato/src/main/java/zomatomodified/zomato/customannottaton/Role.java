package zomatomodified.zomato.customannottaton;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.FIELD, ElementType.ANNOTATION_TYPE, ElementType.CONSTRUCTOR, ElementType.PARAMETER, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Constraint(validatedBy = RoleValidator.class)
public @interface Role {
    public String message() default "Invalid Role(ADMIN,CUSTOMER)";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
