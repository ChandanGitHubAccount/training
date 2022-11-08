package InsuranceDatabases.Service;

import InsuranceDatabases.Model.Car;

import java.util.List;
import java.util.Optional;

public interface CarServiceInterface {
    Car addCar(Car car);

    List<Car> getAllCar();

    Optional<Car> getParticularCarDetails(int carRegNo);
}
