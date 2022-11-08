package Septemper1;

import java.util.Scanner;
class MarksException extends Exception{
    MarksException() {
        super("Internal marks is exceed");
    }
    MarksException(String message) {
        super(message);
    }
}
public class StudentMarksException {
    public static void main(String args[]){
        Scanner scan = new Scanner(System.in);
        System.out.println("enter the internal marks and external marks of student");
        int internalMarks = scan.nextInt(), externalMarks = scan.nextInt();
        try{
            if(internalMarks>40) {
                throw new MarksException();
            }
            else if (externalMarks>60) {
                throw new MarksException("External marks is exceed");
            }
        }
        catch (MarksException e){
            System.out.println(e.getMessage());
        }
    }
}
