package RelationshipEntityOfJpa.Controller;

import RelationshipEntityOfJpa.Model.Students;
import RelationshipEntityOfJpa.Service.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
public class StudentController {
    @Autowired
    private StudentService studentService;

    @PostMapping("/add")
    public ResponseEntity<Students> addStudentDetails(@RequestBody Students student){
        try {
            return ResponseEntity.of(Optional.of(studentService.addStudentDetails(student)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }
    @GetMapping("/getAllStudentDetails")
    public ResponseEntity<List<Students>> getAllStudentDetails(){
        try {
            return ResponseEntity.of(Optional.of(studentService.getAllStudentDetails()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
