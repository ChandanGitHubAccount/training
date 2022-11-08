package example.demo.Controller;

import example.demo.Model.Student;
import example.demo.Service.StudentServiceInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class StudentController {
    @Autowired
    StudentServiceInterface studentServiceInterface;

    @PostMapping("/addStudent:")
    public void aadStudent(@RequestBody Student student){
        studentServiceInterface.addStudentDetails(student);
    }
    @GetMapping("/viewAllStudent:")
    public Map<String , Student> displayAllStudentDetail(){
        return studentServiceInterface.displayStudentDetails();
    }
    @GetMapping("/viewParticularStudentDetail:/{studentId}")
    @ResponseBody
    public Student displayParticularStudentDetail(@PathVariable String studentId){
        return studentServiceInterface.displayStudentDetailsById(studentId);
    }
    @DeleteMapping("/deleteAllStudentDetails:")
    public void clearAllStudentRecord(){
        studentServiceInterface.deleteAllStudentRecords();
    }
    @PostMapping("/addStudentDemo:")
    public void add(){
        studentServiceInterface.studentDetail();
    }
}
