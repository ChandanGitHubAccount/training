package example.InsuranceDatabase.Service;

import example.InsuranceDatabase.Model.Accident;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class AccidentService implements AccidentServiceInterface {

    @Autowired
    JdbcTemplate jdbcTemplate;
    @Override
    public List<Accident> showAllAccidentDetails() {
        try{
            return jdbcTemplate.query("SELECT * FROM accident",new BeanPropertyRowMapper<>(Accident.class));
        }catch (Exception exception){
            System.out.println("Record not found" + exception);
            return null;
        }
    }

    @Override
    public Accident addAccidents(Accident accident) {
        try{
             jdbcTemplate.update("INSERT INTO accident VALUES (? , ? , ?)" , accident.getReport_no(), accident.getAcc_date() , accident.getLocation());
             return accident;
        }catch (Exception exception){
            System.out.println("Invalid Records " + exception);
            return null;
        }
    }

    @Override
    public List<Accident> removeAccidents(int accidentReportNo) {
        try{
            List<Accident> accidentList = jdbcTemplate.query("SELECT * FROM accident WHERE report_no = ?" , new BeanPropertyRowMapper<>(Accident.class) , accidentReportNo);
            jdbcTemplate.update("DELETE FROM accident WHERE report_no = ?",accidentReportNo);
            return accidentList;
        }catch (Exception exception){
            System.out.println("Record not found." + exception);
            return null;
        }
    }
}
