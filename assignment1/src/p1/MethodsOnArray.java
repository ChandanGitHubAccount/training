package p1;

public class MethodsOnArray {
    public int minimumElement(int array[]){
        int min = array[0];
        for(int index = 1;index<array.length ; index++){
            if (min > array[index])
                min = array[index];
        }
        return min;
    }
    public int[] scalingElementInArray(int array[] , int factor){
        for (int index = 0 ; index<array.length ; index++)
            array[index] *= factor;
        return array;
    }

    public int maximumElement(int array[]){
        int max = array[0];
        for(int index = 1;index<array.length ; index++){
            if (max < array[index])
                max = array[index];
        }
        return max;
    }
}
