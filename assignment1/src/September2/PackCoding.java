package September2;

import p1.MethodsOnArray;

import java.util.Scanner;

class PackCoding {
    public static void main(String[] args) {
        MethodsOnArray reference = new MethodsOnArray();
        System.out.println("enter the size of array");
        Scanner scan = new Scanner(System.in);
        int array[] = new int[scan.nextInt()];
        System.out.println("enter the elements of array");
        for(int index=0 ; index<array.length ; index++)
            array[index] = scan.nextInt();
        while (true) {
            System.out.println("enter the choice\n1:find minimum element\n" +
                    "2:find larger element\n" +
                    "3:to scale array by factor\n4:exit ");
            int choice = scan.nextInt();
            switch (choice) {
                case 1:int minimumElementInArray = reference.minimumElement(array);
                System.out.println("minimum elelment in array:"+minimumElementInArray);
                break;
                case 3:System.out.println("enter scalling factor");
                int scaledArray[] = reference.scalingElementInArray(array, scan.nextInt());
                for (int item:scaledArray)
                    System.out.print(item+"\t");
                System.out.println();
                break;
                case 2:int maximumElementInArray = reference.maximumElement(array);
                System.out.println("maximum elelment in array:"+maximumElementInArray);
                break;
                case 4:return;
            }
        }

    }
}
