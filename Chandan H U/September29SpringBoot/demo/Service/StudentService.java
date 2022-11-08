package example.demo.Service;

import example.demo.Model.Student;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
@Service
public class StudentService implements StudentServiceInterface{
    Map<String , Student> studentDetails = new HashMap<>();
    @Override
    public void studentDetail() {
        studentDetails.put("4GH18EC010",new Student("4GH18EC010","chandan","ECE",21));
        studentDetails.put("4GH18EC011",new Student("4GH18EC011","chandu","EEE",22));
        studentDetails.put("4GH18EC012",new Student("4GH18EC012","Sumant","CSE",23));
    }

    @Override
    public Map<String, Student> displayStudentDetails() {
        if(studentDetails.isEmpty())
        return null;
        else return studentDetails;
    }

    @Override
    public Student displayStudentDetailsById(String  studentId) {
        if(studentDetails.containsKey(studentId))
            return studentDetails.get(studentId);
        else return null;
    }

    @Override
    public void addStudentDetails(Student student) {
            studentDetails.put(student.getStudentId(),student);
    }

    @Override
    public void deleteAllStudentRecords() {
            studentDetails.clear();
    }

    @Override
    public void updateStudentDetail(String StudentId) {

    }
}
