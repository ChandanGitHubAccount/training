package zomato.customannottaton;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.Arrays;
import java.util.List;

public class DayValidator implements ConstraintValidator<Day , String >{
    @Override
    public boolean isValid(String day, ConstraintValidatorContext constraintValidatorContext) {
        List<String > days = Arrays.asList("MONDAY","TUESDAY","WEDNESDAY","THURSDAY","FRIDAY","SATURDAY","SUNDAY","NONE");
        return days.contains(day.toUpperCase());
    }
}
