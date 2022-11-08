package DesignEmployee.Employee.Service;

import DesignEmployee.Employee.Model.Employee;

import java.util.HashMap;
import java.util.Map;

public class EmployeeServices implements EmployeeServiceInterface {
    Map<String, Employee> employeeDetails = new HashMap<>();

    @Override
    public Map<String, Employee> displayEmployeeDetails() {
        if (employeeDetails.isEmpty())
            return null;
        else return employeeDetails;
    }

    @Override
    public Employee displayParticularEmployeeDetail(String employeeId) {
        return employeeDetails.getOrDefault(employeeId, null);
    }

    @Override
    public void addEmployeeDetails(Employee employee) {
        employeeDetails.put(employee.getEmployeeId(), employee);
    }

    @Override
    public void deleteParticularEmployeeRecord(String employeeId) {
        employeeDetails.remove(employeeId);
    }

    @Override
    public void updateEmployeeDepartment(String employeeId, String employeeDepartment) {
        if (employeeDetails.containsKey(employeeId))
            employeeDetails.get(employeeId).setEmployeeDepartment(employeeDepartment);
    }
}
