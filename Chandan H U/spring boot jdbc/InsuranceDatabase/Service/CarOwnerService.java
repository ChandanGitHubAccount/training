package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.CarOwner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public class CarOwnerService implements CarOwnerServiceInterface{
    @Autowired
    JdbcTemplate  jdbcTemplate;
    @Override
    public List<CarOwner> viewCarOwnerDetails() {
        try{
            return jdbcTemplate.query("SELECT * FROM owns" , new BeanPropertyRowMapper<>(CarOwner.class));
        }catch (Exception exception){
            System.out.println("Record not found." + exception);
            return null;
        }
    }
}
