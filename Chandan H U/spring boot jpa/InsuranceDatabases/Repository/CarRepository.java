package InsuranceDatabases.Repository;

import InsuranceDatabases.Model.Car;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CarRepository extends JpaRepository<Car,Integer> {
}
