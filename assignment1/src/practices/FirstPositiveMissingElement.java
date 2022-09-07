package practices;

import java.util.Arrays;
import java.util.Scanner;

public class FirstPositiveMissingElement {
    static Scanner scan =new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("enter the size of array");
        int size = scan.nextInt();

        int array[] = new int[size];

        System.out.println("enter the element in array");
        for(int index=0 ; index<size ; index++)
            array[index] = scan.nextInt();

        System.out.println("First missing positive number  in array:"+firstPositiveMissingNumberInArray(array));
    }
    static int firstPositiveMissingNumberInArray(int [] array){
        int sortedArray[] = Arrays.stream(array).sorted().toArray();

        int missingNumber = 1;

        for(int index=0 ; index<array.length ; index++)
             if(sortedArray[index]>0 && sortedArray[index] == missingNumber)
                missingNumber++;

        if(missingNumber == sortedArray[sortedArray.length-1])
            return missingNumber +1;
        else
            return missingNumber;
    }
}
