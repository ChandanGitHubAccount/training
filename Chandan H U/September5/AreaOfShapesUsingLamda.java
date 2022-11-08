package September5;

import java.util.Scanner;
import java.util.function.BiFunction;
import java.util.function.Function;

public class AreaOfShapesUsingLamda {
    public static void main(String[] args) {
        Scanner scan = new Scanner(System.in);

        BiFunction<Double,Double,Double> areaOfRectangle = (lengthOfRectangle, widthOfRectancle) -> lengthOfRectangle * widthOfRectancle;
        BiFunction <Double,Double,Double> areaOfTriangle = (baseOfTriangle,heigthOfTringle) -> (baseOfTriangle * heigthOfTringle) / 2;
        Function <Double,Double> areaOfSquare = (sideOfSquare) -> Math.pow(sideOfSquare,2);
        Function <Double,Double> areaOfCircle = (radiusOfCircle) -> Math.pow(radiusOfCircle,2)*Math.PI;

        //Area of rectangle
        System.out.println("enter the length of Rectangle");
        double lengthOfRectangle = scan.nextDouble();
        System.out.println("enter the  width of Rectangle");
        double widthOfRectancle = scan.nextDouble() ;
        System.out.println("Area of rectangle:"+areaOfRectangle.apply(lengthOfRectangle,widthOfRectancle));

        //Area of Triangle
        System.out.println("enter the length  of Triangle");
        double baseOfTriangle = scan.nextDouble();
        System.out.println("enter the  heigth of trinagle");
        double heigthOfTringle = scan.nextDouble();
        System.out.println("Area of Triangle:"+areaOfTriangle.apply(baseOfTriangle,heigthOfTringle));

        //Area of Square
        System.out.println("enter the side length of  Square");
        double sideOfSquare = scan.nextDouble() ;
        System.out.println("Area of Square:"+areaOfSquare.apply(sideOfSquare));

        //Area of Circle
        System.out.println("enter the radius  of Circle");
        double radiusOfCircle = scan.nextDouble();
        System.out.println("Area of Circle:"+areaOfCircle.apply(radiusOfCircle));
    }
}
