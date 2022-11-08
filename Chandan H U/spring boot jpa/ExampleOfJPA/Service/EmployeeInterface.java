package ExampleOfJPA.Service;

import ExampleOfJPA.Model.EmployeeData;

import java.util.Optional;

public interface EmployeeInterface {
    Optional<EmployeeData> findAllRecordsById(long employeeId);

    EmployeeData addEmployeeDetails(EmployeeData employeeData);
}
