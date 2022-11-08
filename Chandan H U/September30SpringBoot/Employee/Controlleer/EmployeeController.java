package DesignEmployee.Employee.Controlleer;

import DesignEmployee.Employee.Model.Employee;
import DesignEmployee.Employee.Service.EmployeeServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class EmployeeController {
    @Autowired
    EmployeeServiceInterface employeeServiceInterface;

    @PostMapping("/addEmployeeDetails:")
    public void addEmployeeDetails(@RequestBody Employee employee) {
        employeeServiceInterface.addEmployeeDetails(employee);
    }

    @GetMapping("/viewAllEmployeeDetails:")
    public Map<String, Employee> DisplayAllRecordsOfEmployee() {
        return employeeServiceInterface.displayEmployeeDetails();
    }

    @GetMapping("/viewParticularEmployeeDetails:{employeeId}")
    public Employee displayParticularEmployeeDetails(@PathVariable String employeeId) {
        return employeeServiceInterface.displayParticularEmployeeDetail(employeeId);
    }

    @DeleteMapping("/deleteEmployeeDetails:{employeeId}")
    public void deleteEmployeeRecordByEmployeeId(@PathVariable String employeeId) {
        employeeServiceInterface.deleteParticularEmployeeRecord(employeeId);
    }

    @PutMapping("/updateEmployeeDetails:{employeeId}")
    public void updateEmployeeDetails(@PathVariable String employeeId, @RequestBody String employeeDepartment) {
        employeeServiceInterface.updateEmployeeDepartment(employeeId, employeeDepartment);
    }
}
