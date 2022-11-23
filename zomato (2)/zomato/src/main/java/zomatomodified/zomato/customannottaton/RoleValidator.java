package zomatomodified.zomato.customannottaton;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.List;

public class RoleValidator implements ConstraintValidator<Role, String> {
    @Override
    public boolean isValid(String role, ConstraintValidatorContext constraintValidatorContext) {
        List<String> roles = Arrays.asList("ADMIN", "CUSTOMER");
        return roles.contains(role.toUpperCase());
    }
}
