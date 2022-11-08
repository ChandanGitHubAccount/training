package September9;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class StudentDetialUsingMap {
    public static void main(String[] args)
    {
        // Creating an empty Linked Hash Map
        Map<String, String> students = new LinkedHashMap<>();
        // Adding data to Linked Hash Map in key-value pair
        students.put("RT1", "Chandan");
        students.put("RT2", "Gayana");
        students.put("RT3", "Sumanth");
        students.put("RT4", "Vijayalakshmi");
        students.put("RT5", "Vilas");
        students.put("RT6","Namratha");
        students.put("RT7","Vinyshree");
        // Showing size and data of the Linked Hash Map
        System.out.println("The size of the Linked Hash Map is: "+ students.size());
        System.out.println(students+"\n");
        // Checking whether a certaint key is available or not
        Scanner scan = new Scanner(System.in);
        Set<String> keys = students.keySet();
        System.out.println("The keys are: "+keys);
        System.out.println("enter the id of student:");
        String studentId = scan.next();
        if (students.containsKey(studentId)) {
            String studentName = students.get(studentId);
            System.out.println("The name of the student having Id RT4 is: " + studentName);
        }
        else System.out.println("Student detils not found");
        System.out.println();
        for(String key:keys)
        if (students.containsKey(key)) {
            String studentName = students.get(key);
            System.out.println("The name of the student having Id RT4 is: " + studentName);
        }
        else System.out.println("Student detils not found");

    }
}
