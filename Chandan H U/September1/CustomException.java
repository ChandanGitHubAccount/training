package Septemper1;

import java.util.Scanner;
class MraksErrorException extends Exception{
    MraksErrorException(){
        super("Total marks is more than 100 so enter the valid marks");
    }
}
public class CustomException {
    static int checkSum(int internalMarks , int externalMarks){
        return internalMarks+externalMarks;
    }
    public static void main(String args[]){
        Scanner scan = new Scanner(System.in);
        int internalMArks = scan.nextInt(),externalMarks = scan.nextInt();
        try {
            if(checkSum(internalMArks, externalMarks)>100)
               throw new MraksErrorException();
            else
                System.out.println("entered marks are valid");
        }
        catch (MraksErrorException e) {
            System.out.println(e.getMessage());
        }

    }

}
