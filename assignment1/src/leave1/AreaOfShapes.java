package leave1;

import java.util.Scanner;

abstract class Shapes{
    Scanner scan = new Scanner(System.in);
    double width,hegith;
    abstract void getAreas() ;
}

class Rectangles extends Shapes{
    void getAreas(){
        System.out.println("enter the heigth and width of rectangle");
        width = scan.nextDouble();
        hegith = scan.nextDouble();
        System.out.println("The area of rectangle :"+(hegith*width));
    }
}

class Tringle extends Shapes{
    void getAreas(){
        System.out.println("enter the heigth and width of triangle");
        width = scan.nextDouble();
        hegith = scan.nextDouble();
       System.out.println("the area of triangle:"+((hegith*width)/2));
    }
}

class Square extends Shapes{
    void getAreas(){
        System.out.println("enter the width of square");
        width = scan.nextDouble();
        System.out.println("the area of square:"+(width*width));
    }
}
public class AreaOfShapes {
    public static void main(String agrs[]) {
        Scanner scan = new Scanner(System.in);
        while (true) {
            System.out.println("enter \n1:area of rectangle\n2:area of trinagle\n3:area of square\n4:exit");
            int choice = scan.nextInt();
            switch (choice) {
                case 1:
                    Rectangles rectangle = new Rectangles();
                    rectangle.getAreas();
                    break;
                case 2:
                    Tringle triangle = new Tringle();
                    triangle.getAreas();
                    break;
                case 3:
                    Square square = new Square();
                    square.getAreas();
                    break;
                case 4:
                    return;
            }
        }
    }
}
