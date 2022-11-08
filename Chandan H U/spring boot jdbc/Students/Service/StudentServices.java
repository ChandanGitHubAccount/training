package example.Students.Service;

import example.Students.Model.Studentinfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public class StudentServices implements StudentInterfaces {
    @Autowired
    JdbcTemplate jdbcTemplate;

    @Override
    public List<Studentinfo> displayStudentDetail() {
        try {
            return jdbcTemplate.query("SELECT * FROM tableStudent", new BeanPropertyRowMapper<>(Studentinfo.class));
        }catch (Exception exception){
            System.out.println("student details not found");
            System.out.println(exception);
            return null;
        }
    }

    @Override
    public Studentinfo displayParticularStudentDetail(String studentUSN) {
        try {
            return jdbcTemplate.queryForObject("SELECT * FROM tableStudent where studentUSN=?",
                    new BeanPropertyRowMapper<>(Studentinfo.class), studentUSN);
        }catch (Exception exception){
            System.out.println("student not exit");
            System.out.println(exception);
            return null;
        }
    }

    @Override
    public void addStudentDetails(Studentinfo studentinfo) {
        try{
            jdbcTemplate.update("INSERT INTO tableStudent VALUES (? , ? , ?, ?, ?)", studentinfo.getStudentUSN(),
                    studentinfo.getStudentName(), studentinfo.getStudentCourse(), studentinfo.getStudentEmail(),
                    studentinfo.getStudentMobileNumbers());
        }catch (Exception exception){
            System.out.println(exception);
        }
    }

    @Override
    public void deleteParticularStudentsRecord(String studentUSN) {
        try{
            jdbcTemplate.update("DELETE FROM tableStudent WHERE studentUSN=?", studentUSN);
        }catch (Exception exception){
            System.out.println("record not found");
            System.out.println(exception);

        }
    }

    @Override
    public void updateStudentMobileNumber(String studentUSN, long studentMobileNumber) {
        try{
            jdbcTemplate.update("update tableStudent set studentMobileNumbers = ? where studentUSN = ?",
                    studentMobileNumber, studentUSN);
        }catch (Exception exception){
            System.out.println("data not exit");
            System.out.println(exception);
        }
    }
}
