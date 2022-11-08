package InsuranceDatabases.Service;

import InsuranceDatabases.Model.Car;
import InsuranceDatabases.Repository.CarRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CarService implements CarServiceInterface {

    @Autowired
    private CarRepository carRepository;

    @Override
    public Car addCar(Car car) {
        try {
            return carRepository.save(car);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<Car> getAllCar() {
        try {
            return carRepository.findAll();
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public Optional<Car> getParticularCarDetails(int carRegNo) {
        try {
            return carRepository.findById(carRegNo);
        } catch (Exception exception) {
            exception.printStackTrace();
            return Optional.empty();
        }
    }
}
