package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Car;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class CarService implements CarServiceInterface {

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Override
    public Car addCar(Car car) {
        try{
            jdbcTemplate.update("INSERT INTO car VALUES(? , ? , ?)",car.getRegNo(),car.getModle(),car.getYear());
            return car;
        }catch (Exception exception){
            System.out.println("Invalid details.");
            return null;
        }
    }

    @Override
    public List<Car> remove(String carRegNo) {
        try{
            List<Car> carList = jdbcTemplate.query("select * from car where regno = ?",new BeanPropertyRowMapper<>(Car.class) , carRegNo);
        jdbcTemplate.update("DELETE FROM car WHERE regno = ? ",carRegNo);
        return carList;
        }catch (Exception exception){
            System.out.println("Record not found." + exception);
            return null;
        }
    }

    @Override
    public List<Car> viewAllCarDetails() {
        try{
            return jdbcTemplate.query("SELECT * FROM car",new BeanPropertyRowMapper<>(Car.class));
        }catch (Exception exception){
            System.out.println("Record Not found.");
            return null;
        }
    }
}
