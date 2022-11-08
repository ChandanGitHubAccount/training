package ExampleOfJPA.Repositary;

import ExampleOfJPA.Model.EmployeeData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;


public interface EmployeeRepository extends JpaRepository<EmployeeData, Long> {
    List<EmployeeData> findByEmployeeProfession(String employeeProfession);

    long countByEmployeeAge(int employeeAge);

    void deleteByEmployeeId(long employeeId);

    List<EmployeeData> findByEmployeeProfessionAndEmployeeAge(String employeeProfession, int employeeAge);

    List<EmployeeData> findByEmployeeProfessionIgnoreCase(String employeeProfession);

    Optional<EmployeeData> findByEmployeeId(long employeeId);

    @Query(value = "SELECT * FROM Employee_Data WHERE employee_Id = :employeeId",nativeQuery = true)
    EmployeeData getUsersCustomQuery(@Param("employeeId") long employeeId);
}
