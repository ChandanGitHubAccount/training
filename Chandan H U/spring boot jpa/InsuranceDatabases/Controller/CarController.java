package InsuranceDatabases.Controller;

import InsuranceDatabases.Model.Car;
import InsuranceDatabases.Service.CarService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/car/")
public class CarController {

    @Autowired
    private CarService carService;

    @PostMapping("addCar")
    public ResponseEntity<Car> addAccident(@RequestBody Car car){
        try {
            return ResponseEntity.of(Optional.of(carService.addCar(car)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("getAllCarDetails")
    public ResponseEntity<List<Car>> getAllAccidentDetails(){
        try {
            return ResponseEntity.of(Optional.of(carService.getAllCar()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
    }

    @GetMapping("getParticularCarDetails/{carRegNo}")
    public ResponseEntity<Optional<Car>> getParticularAccidentDetails(@PathVariable int carRegNo){
        try {
            return ResponseEntity.of(Optional.of(carService.getParticularCarDetails(carRegNo)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
