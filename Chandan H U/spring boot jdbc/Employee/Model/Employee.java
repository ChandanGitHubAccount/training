package example.Employee.Model;

public class Employee {
    private String employeeName, employeeId, employeeDepartment, employeeLocation;

    public Employee(String employeeName , String employeeId , String employeeDepartment , String employeeLocation) {
        this.employeeName = employeeName;
        this.employeeId = employeeId;
        this.employeeDepartment = employeeDepartment;
        this.employeeLocation = employeeLocation;
    }

    public String getEmployeeLocation() {return employeeLocation;}

    public void setEmployeeLocation(String employeeLocation) {this.employeeLocation = employeeLocation;}

    public String getEmployeeDepartment() {return employeeDepartment;}

    public void setEmployeeDepartment(String employeeDepartment) {this.employeeDepartment = employeeDepartment;}

    public String getEmployeeId() {return employeeId;}

    public void setEmployeeId(String employeeId) {this.employeeId = employeeId;}

    public String getEmployeeName() {return employeeName;}

    public void setEmployeeName(String employeeName) {this.employeeName = employeeName;}

}
