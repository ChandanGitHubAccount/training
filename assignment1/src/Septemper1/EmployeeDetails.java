package Septemper1;

import java.util.ArrayList;
import java.util.Scanner;

class Employee{
    String emplyeeName,employeeId;
    int employeeSalary;
    Employee(String emplyeeName,String employeeId,int employeeSalary){
        this.emplyeeName = emplyeeName;
        this.employeeId = employeeId;
        this.employeeSalary=employeeSalary;
    }
}
public class EmployeeDetails {
    public static void main(String agrs[]) {
        ArrayList<Employee> employee = new ArrayList<Employee>();
        String emplyeeName, employeeId;
        int employeeSalary, choice;
        Scanner scan = new Scanner(System.in);
        while (true) {
            System.out.println("enter the choice\n1:Insert a record \n" +
                    "2:Delete a record (based on the Id) \n" +
                    "3:Display the record\n4:to update employee record\n5:exit ");
            choice = scan.nextInt();
            switch (choice) {
                case 1:
                    System.out.println("enter the emplyee name");
                    emplyeeName = scan.next();
                    System.out.println("enter the emplyee id");
                    employeeId = scan.next();
                    System.out.println("enter the emplyee salary");
                    employeeSalary = scan.nextInt();
                    employee.add(new Employee(emplyeeName, employeeId, employeeSalary));
                    break;
                case 2:
                    System.out.println("enter the emplyee id to delete records");
                    String employeeIdRef = scan.next();
                    Employee employeeReference = null;
                    for (Employee itemsInArrayList : employee)
                        if (itemsInArrayList.employeeId.equals(employeeIdRef)) {
                            employeeReference = itemsInArrayList;
                            break;
                        }
                        if (employeeReference == null)
                            System.out.println("employee doesnot exist");
                        else
                            employee.remove(employeeReference);
                        break;
                case 3:
                    System.out.println("name"+"\t"+"id"+"\t"+"salary");
                    for (Employee itemsInArrayList : employee)
                        System.out.println(itemsInArrayList.emplyeeName +"\t"+itemsInArrayList.employeeId +"\t"+itemsInArrayList.employeeSalary);
                    break;
                case 4:System.out.println("enter the emplyee id to update records");
                    String employeeIdRefe = scan.next();
                    for (Employee itemsInArrayList : employee)
                        if (itemsInArrayList.employeeId.equals(employeeIdRefe)) {
                            while (true) {
                                System.out.println("enter\n1:updated salary\n2:update name\n3:update id\n4:exit");
                                int choices = scan.nextInt();
                                switch (choices) {
                                    case 1:
                                        System.out.println("enter updated salary");
                                        itemsInArrayList.employeeSalary = scan.nextInt();
                                        break;
                                    case 2:
                                        System.out.println("enter updated name");
                                        itemsInArrayList.emplyeeName = scan.next();
                                        break;
                                    case 3:
                                        System.out.println("enter updated id");
                                        itemsInArrayList.employeeId = scan.next();
                                        break;
                                    case 4:
                                        return;
                                }

                                break;
                            }
                        }
                    break;
                case 5:
                   return;

            }
        }


    }
}
