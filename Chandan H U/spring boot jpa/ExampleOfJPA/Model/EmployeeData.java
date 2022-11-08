package ExampleOfJPA.Model;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Entity
public class EmployeeData {
    @Id
    private long employeeId;
    private String employeeName;
    private LocalDate employeeSateOfBirth;
    private int employeeAge;
    private String employeeGender;
    private String employeeProfession;
    private long employeePhoneNumber;
    private String employeeAddress;
}
