package Septemper1;

import java.util.ArrayList;
import java.util.Scanner;

public class Employeee {
    public static void main(String args[]) {
        Scanner scan = new Scanner(System.in);
        System.out.println("enter the number of employee");
        int numberOfEmpyoyee = 5;
        ArrayList<String> employeeName = new ArrayList<String>(numberOfEmpyoyee);
        ArrayList<Integer> employeeId = new ArrayList<Integer>(numberOfEmpyoyee);
        ArrayList<Integer> employeeSalary = new ArrayList<Integer>(numberOfEmpyoyee);
        do {
            System.out.println("enter the choice\n1:Insert a record \n" +
                    "2:Delete a record (based on the Id) \n" +
                    ":Display the record ");
            int choice = scan.nextInt();

            switch (choice) {
                case 1: System.out.println("enter the employee name");
                String name = scan.next();
                employeeName.add(name);
                System.out.println("enter the employee id");
                int id = scan.nextInt();
                employeeId.add(id);
                System.out.println("enter the employee salary");
                int salary = scan.nextInt();
                case 2: System.out.println("enter the employee id to delete the record");

                case 3:
            }
        } while (true);
    }
}
