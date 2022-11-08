package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Car;

import java.util.List;

public interface CarServiceInterface {
    Car addCar(Car car);
    List<Car> remove(String carRegNo);
    List<Car> viewAllCarDetails();
}
