package assignment3;

import java.util.Scanner;
import java.lang.*;
public class StringFunctions {
    public static void main(String args[]){
        Scanner scan = new Scanner(System.in);
        Functions object = new Functions();
        System.out.println("enter the string");
        StringBuffer string = new StringBuffer(scan.nextLine());
        System.out.println("choose the operation to be performed\n1:to find substring\n2:to delete character at given index\n3: to  replaces the characters in a substring\n4:reverse a string\n" +
                "5:to find  duplicate words\n6:to merge the capital letter of two string");
        int choice = scan.nextInt();
        switch (choice){
            case 1: System.out.println("enter the substring need to be find");
            StringBuffer subString = new StringBuffer(scan.next());
            System.out.println(object.findSubString(string,subString));
            break;
            case 2:System.out.println("enter the index of character to be removed");
            int index = scan.nextInt();
            System.out.println(object.deleteCharAt(string,index));
            break;
            case 3:System.out.println("enter the substring need to be replaced");
            StringBuffer subString1 = new StringBuffer(scan.next());
            System.out.println("enter the newstring to be replaced");
            StringBuffer newString = new StringBuffer(scan.next());
            System.out.println(object.replaceSubString(string,subString1,newString));
            break;
            case 4:System.out.println(object.reverseString(string));
            break;
            case 5:System.out.println("the duplicate words are:");
            object.duplicateWordsInString(string);
            break;
            case 6:System.out.println("enter the 1st string");
            StringBuffer string1 = new StringBuffer(scan.next());
            System.out.println("enter the 2nd string");
            StringBuffer string2 = new StringBuffer(scan.next());
            System.out.println(" capital letters from both the strings:");
            object.mergedStrings(string1,string2);
            break;
            default:
               System.out.println("invalid choice");
        }

    }
}
