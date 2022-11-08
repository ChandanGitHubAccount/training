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
        return jdbcTemplate.query("SELECT * FROM tableStudent", new BeanPropertyRowMapper<>(Studentinfo.class));
    }

    @Override
    public Studentinfo displayParticularStudentDetail(String studentUSN) {
        return jdbcTemplate.queryForObject("SELECT * FROM tableStudent where studentUSN=?",
                new BeanPropertyRowMapper<>(Studentinfo.class),studentUSN);
    }

    @Override
    public void addStudentDetails(Studentinfo studentinfo) {
        jdbcTemplate.update("INSERT INTO tableStudent VALUES (? , ? , ?, ?, ?)", studentinfo.getStudentUSN(),
                studentinfo.getStudentName(), studentinfo.getStudentCourse(), studentinfo.getStudentEmail(),
                studentinfo.getStudentMobileNumbers());
    }

    @Override
    public void deleteParticularStudentsRecord(String studentUSN) {
        jdbcTemplate.update("DELETE FROM tableStudent WHERE id=?", studentUSN);
    }

    @Override
    public void updateStudentMobileNumber(String studentUSN, long studentMobileNumber) {
        jdbcTemplate.update("update tableStudent set studentMobileNumbers = ? where studentUSN = ?",
                studentMobileNumber, studentUSN);
    }
}
