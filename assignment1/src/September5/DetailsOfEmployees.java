package September5;

import java.util.*;
import java.util.stream.Collectors;

class Informations{
    String employeeName,employeeId;
    double employeeSalary;
    Informations(String employeeName,String employeeId,double employeeSalary){
        this.employeeId = employeeId;
        this.employeeName = employeeName;
        this.employeeSalary = employeeSalary;
    }
}
public class DetailsOfEmployees {
    static List<Informations> employee = new ArrayList<>();
    static Scanner scan = new Scanner(System.in);

    public static void main(String[] args) {

        int choose;
        do {
            recordEmployeeDetial();
            System.out.println("enter 1 to add employee record or 0 to exit");
            choose = scan.nextInt();
        } while (choose == 1);

        while (true) {
            System.out.println("""
                    choose\s
                    1:Find the employee with  salary >15000\s
                    2:Find the employee name starts with letter ‘ V”\s
                    3:Find the maximum salary\s
                    4:Find the total number of empoyees\s
                    5:Find the employee name length more than four.\s
                    6:Sort the employee details based on name\s
                    7:exit""");
            int choice = scan.nextInt();
            switch (choice) {
                case 1:
                    List<Informations> salarymoreThan15000 = employeeSalaryGreaterThan15000(employee);
                    salarymoreThan15000.forEach(info -> System.out.println(info.employeeName+"\t"+info.employeeId+"\t"+info.employeeSalary));
                    break;
                case 2:
                    List<Informations> nameStartWithV = employeeNameStartsWithV(employee);
                    nameStartWithV.forEach(info -> System.out.println(info.employeeName+"\t"+info.employeeId+"\t"+info.employeeSalary));
                    break;
                case 3:
                    Optional<Informations> maximumSalary = employeeMaximumSalary(employee);
                    System.out.print(maximumSalary.get().employeeName+"\t"+maximumSalary.get().employeeSalary+"\t"+maximumSalary.get().employeeId+"\n");
                    break;
                case 4:
                    double numberOfEmployee = totalNumberOfEmployee(employee);
                    System.out.println(numberOfEmployee);
                    break;
                case 5:
                    List<Informations> lengthMoreThan15 = employeeNameLengthMoreThan15(employee);
                    lengthMoreThan15.forEach(info -> System.out.println(info.employeeName+"\t"+info.employeeId+"\t"+info.employeeSalary));
                    break;
                case 6:
                    List<Informations> sortingNames = sortingempyloyeeRecordsbyNames(employee);
                    sortingNames.forEach(info -> System.out.println(info.employeeName+"\t"+info.employeeId+"\t"+info.employeeSalary));
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
        employee.add(new Informations(emplyeeName, employeeId, employeeSalary));
    }

    private static List<Informations> employeeSalaryGreaterThan15000(List<Informations> employee){
        return employee.stream().filter(salary -> (salary.employeeSalary>15000)).collect(Collectors.toList());
    }
    private static List<Informations> employeeNameStartsWithV(List<Informations> employee){
        return employee.stream().filter((Name -> Name.employeeName.startsWith("V"))).collect(Collectors.toList());

    }
    private static Optional<Informations> employeeMaximumSalary(List<Informations> employee){
        return employee.stream().max(Comparator.comparing(salary -> salary.employeeSalary));
    }
    private static double totalNumberOfEmployee(List<Informations> employee){
    return employee.stream().count();
    }
    private static List<Informations> employeeNameLengthMoreThan15(List<Informations> employee){
        return employee.stream().filter(lengths -> lengths.employeeName.length()>15).collect(Collectors.toList());
    }

    private static List<Informations> sortingempyloyeeRecordsbyNames(List<Informations> employee){
        return employee.stream().sorted(Comparator.comparing(name -> name.employeeName)).collect(Collectors.toList());
    }
}
