package practices;

import java.util.ArrayList;
import java.util.Scanner;

class FunctionByLamda{
    static int leastElement(ArrayList<Integer> arrayList) {
         int min = arrayList.get(0);
        for (int i = 1; i < arrayList.size(); i++)
            if ((arrayList.get(i)) < min)
                min = arrayList.get(i);
        return min;
    }

    static void Scale(ArrayList<Integer> arrayList , int f){
        arrayList.forEach(e->{
            e = e * f;
            System.out.print(e+"\t");
        });
        arrayList.forEach(i-> {
            System.out.print(i + "\t");
        });
    }
}


public class LamdaPractice {

    static  ArrayList<Integer> array = new ArrayList<Integer>();
    static Scanner scan = new Scanner(System.in);
    public static void main(String args[]){
        FunctionByLamda obj = new FunctionByLamda();
        System.out.println("enter the array element");
        int choice;
        do{
            array.add(scan.nextInt());
            System.out.println("enter 1 to add more elemnts or 0 to quit");
            choice = scan.nextInt();
        }while (choice == 1);
        System.out.println(obj.leastElement(array));
        obj.Scale(array,2);

    }
}
