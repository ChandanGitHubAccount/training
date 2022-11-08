package September8;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class StudentAverageMarksCalculationInFile {
    public static void main(String[] args) throws FileNotFoundException {
        Scanner scan = new Scanner(System.in);
        System.out.println("enter the file name along with path");
        File file = new File(scan.next());
        System.out.println("enter the number of subjet");
        int numberOfSubject = scan.nextInt(), i = 1;

        Scanner newFile = new Scanner(file);

        while (newFile.hasNextLine()) {
            String marks[] = newFile.nextLine().split(" ");
            double totalMarks = 0;
            for (String mark : marks) totalMarks = totalMarks + Double.parseDouble(mark);

            System.out.println("the average of student " + i++ + " :" + totalMarks / numberOfSubject);

        }
    }
}
