package example.Employee.Service;

import example.Employee.Model.Employee;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
@Service
public class EmployeeService implements EmployeeServiceInterface{
    Map<String, Employee> employeeDetails = new HashMap<>();

    @Override
    public Map<String, Employee> displayEmployeeDetails() {
        if (employeeDetails.isEmpty())
            return null;
        else return employeeDetails;
    }

    @Override
    public Employee displayParticularEmployeeDetail(String employeeId) {
        try {
            return employeeDetails.get(employeeId);
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public void addEmployeeDetails(Employee employee) {
        employeeDetails.put(employee.getEmployeeId(), employee);
    }

    @Override
    public void deleteParticularEmployeeRecord(String employeeId) {
        try {
            employeeDetails.remove(employeeId);
        }catch (Exception exception){
           exception.printStackTrace();
        }
    }

    @Override
    public void updateEmployeeDepartment(String employeeId, String employeeDepartment) {
        try {
            if (employeeDetails.containsKey(employeeId))
                employeeDetails.get(employeeId).setEmployeeDepartment(employeeDepartment);
        }catch (Exception exception){
            exception.printStackTrace();
        }
    }
}
