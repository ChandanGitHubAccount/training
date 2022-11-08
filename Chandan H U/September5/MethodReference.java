package September5;

import java.util.Scanner;
import java.util.function.BiFunction;
import java.util.function.Function;

public class MethodReference {
    static Scanner scan = new Scanner(System.in);
    public static void main(String[] args) {

       /* BiFunction<Double,Double,Double> areaOfRectangle = (lengthOfRectangle, widthOfRectancle) -> MethodReferenceFunctions.retangleArea(lengthOfRectangle, widthOfRectancle);
        BiFunction <Double,Double,Double> areaOfTriangle = (baseOfTriangle,heigthOfTringle) -> MethodReferenceFunctions.triangleArea(baseOfTriangle,heigthOfTringle);
        Function<Double,Double> areaOfSquare = (sideOfSquare) -> MethodReferenceFunctions.squareArea(sideOfSquare);
        Function <Double,Double> areaOfCircle = (radiusOfCircle) -> MethodReferenceFunctions.circleArea(radiusOfCircle);*/

        BiFunction<Double,Double,Double> areaOfRectangle =  MethodReferenceFunctions::retangleArea;
        BiFunction <Double,Double,Double> areaOfTriangle = MethodReferenceFunctions::triangleArea;
        Function<Double,Double> areaOfSquare =  MethodReferenceFunctions::squareArea;
        Function <Double,Double> areaOfCircle =MethodReferenceFunctions::circleArea;

        System.out.println("The area of rectangle:"+areaOfRectangle.apply(2.0,3.5));
        System.out.println("The area of triangle:"+areaOfTriangle.apply(2.3,4.2));
        System.out.println("The area of square:"+areaOfSquare.apply(2.5));
        System.out.println("The area of circle:"+areaOfCircle.apply(5.75));

    }
}

class MethodReferenceFunctions{
    static double retangleArea(double lengthOfRectangle,double widthOfRectancle){
        return lengthOfRectangle*widthOfRectancle;
    }
    static double triangleArea(double baseOfTriangle,double heigthOfTringle){
        return (baseOfTriangle * heigthOfTringle) / 2;
    }
    static double squareArea(double sideOfSquare){
        return Math.pow(sideOfSquare,2);
    }
    static double circleArea(double radiusOfCircle){
        return Math.pow(radiusOfCircle,2)*Math.PI;
    }
}