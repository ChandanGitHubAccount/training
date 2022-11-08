package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Participated;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public class ParticipatedServices implements ParticipatedServicesInterface {
    @Autowired
    JdbcTemplate jdbcTemplate;

    @Override
    public Integer totalNumberOfAccidentHappenInGivenYear(int year) {
        try{
            return jdbcTemplate.queryForObject("select count(driver_id) as number_of_people from participated \n" +
                    "where report_no in(select report_no from accident where year(acc_date) = ?)" , Integer.class , year);
        }catch (Exception exception){
            System.out.println("Record not found." + exception);
            return null;
        }
    }

    @Override
    public Integer numberAccidentMadeByParticularPerson(String personName) {
        try{
            return jdbcTemplate.queryForObject("select count(report_no) as Number_of_accident_by_RAHUL from participated " +
                    "where driver_id in(select id from person where name = ?)" , Integer.class , personName);
        }catch (Exception exception){
            System.out.println("Invalid Query." + exception);
            return null;
        }
    }

    @Override
    public List<Participated> viewAllParticipatedDetails() {
        try{
            return jdbcTemplate.query("SELECT * FROM participated" , new BeanPropertyRowMapper<>(Participated.class));
        } catch (Exception exception){
            System.out.println("Not found." + exception);
            return null;
        }
    }

    @Override
    public Integer updateParticipatedDamageAmount(String carRegNo, int accidentReportNo, Integer amount) {
        try{
            jdbcTemplate.update(" update participated set damage_amt = ? where report_no = ? and regno = ?" , amount  , accidentReportNo , carRegNo);
            return amount;
        }catch (Exception exception){
            System.out.println("Correct Data Not Found. " + exception);
            return null;
        }
    }
}
