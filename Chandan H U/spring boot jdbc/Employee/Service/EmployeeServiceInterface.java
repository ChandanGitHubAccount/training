package example.Employee.Service;

import example.Employee.Model.Employee;

import java.util.Map;

public interface EmployeeServiceInterface {
    Map<String , Employee> displayEmployeeDetails();

    Employee displayParticularEmployeeDetail(String employeeId);

    void addEmployeeDetails(Employee employee);

    void deleteParticularEmployeeRecord(String employeeId);

    void updateEmployeeDepartment(String employeeId , String employeeDepartment);

}
