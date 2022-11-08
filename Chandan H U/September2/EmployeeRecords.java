package September2;

import java.util.LinkedList;
import java.util.Scanner;
class Employees{
    String employeeName,employeeId;
    double salary;
    Employees(String employeeName , String employeeId , double salary){
        this.employeeName = employeeName;
        this.employeeId = employeeId;
        this.salary = salary;
    }

}

public class EmployeeRecords {
    static Scanner scan = new Scanner(System.in);
    static LinkedList<Employees> employee = new LinkedList<Employees>();

    public static void main(String args[]) {

        while (true) {
            System.out.println("enter the choice\n1:Insert a record \n" +
                    "2:Delete a record (based on the Id) \n" +
                    "3:Display the record\n4:to update employee record\n5:higest salary\n6:lowest salary\n7:exit ");
            int choice = scan.nextInt();
            switch (choice) {
                case 1: recordEmployeeDetial();
                break;
                case 2:deleteEmplyeeRecords();
                break;
                case 3:displayEmployeeRecords();
                break;
                case 4:updateEmployeeRecord();
                break;
                case 5:System.out.println("The higest salary in employee records:"+findHigestSalary());
                break;
                case 6:System.out.println("The higest salary in employee records:"+findLowestSalary());
                break;
                case 7:return;
            }

        }
    }
    private static void recordEmployeeDetial(){
        System.out.println("enter the emplyee name");
        String emplyeeName = scan.next();
        System.out.println("enter the emplyee id");
        String employeeId = scan.next();
        System.out.println("enter the emplyee salary");
        double employeeSalary = scan.nextInt();
        employee.add(new Employees(emplyeeName, employeeId, employeeSalary));
    }

    private static void deleteEmplyeeRecords(){
        System.out.println("enter the emplyee id to delete records");
        Employees employeeReference = searchEmployeeRecord(scan.next());
        if (employeeReference == null)
            System.out.println("employee doesnot exist");
        else
            employee.remove(employeeReference);
    }

    private static void displayEmployeeRecords(){
        System.out.println("name"+"\t"+"id"+"\t"+"salary");
        for (Employees itemsInArrayList : employee)
            System.out.println(itemsInArrayList.employeeName +"\t"+itemsInArrayList.employeeId +"\t"+itemsInArrayList.salary);
    }

    private static void updateEmployeeRecord(){
        System.out.println("enter the emplyee id to update records");
        Employees employeeReference = searchEmployeeRecord(scan.next());
        if(employeeReference != null)
            while (true) {
                System.out.println("enter\n1:updated salary\n2:update name\n3:update id\n4:exit");
                int choices = scan.nextInt();
                switch (choices) {
                    case 1:
                        System.out.println("enter updated salary");
                        employeeReference.salary = scan.nextInt();
                        break;
                    case 2:
                        System.out.println("enter updated name");
                        employeeReference.employeeName = scan.next();
                        break;
                    case 3:
                        System.out.println("enter updated id");
                        employeeReference.employeeId = scan.next();
                        break;
                    case 4:
                        return;
                }
            }
        else
            System.out.println("employee record not exist");
    }
    private static Employees searchEmployeeRecord(String employeeIdRef){
        Employees employeeReference = null;
        for (Employees itemsInArrayList : employee)
            if (itemsInArrayList.employeeId.equals(employeeIdRef)) {
                employeeReference = itemsInArrayList;
                break;
            }
        return employeeReference;
    }

    private static double findHigestSalary(){
        double higestSalary = 0 ;
        for(Employees amount:employee)
            if(higestSalary< amount.salary)
                higestSalary = amount.salary;
        return higestSalary;

    }

    private static double findLowestSalary(){
        double lowestSalary = employee.get(0).salary ;
        for(Employees amount:employee)
            if(lowestSalary > amount.salary)
                lowestSalary = amount.salary;
        return lowestSalary;
    }

}
